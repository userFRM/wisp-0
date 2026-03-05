use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::Path;
use std::time::{Duration, Instant};
use wisp_core::chunk_id::h128;
use wisp_core::chunker;
use wisp_core::frame::Frame;
use wisp_core::ict::Ict;
use wisp_core::manifest::{self, Manifest, ManifestEntry};
use wisp_core::recipe::Recipe;
use wisp_core::recipe_ops;
use wisp_core::replay::ReplayWindow;
use wisp_core::ssx_decoder::SsxDecoder;
use wisp_core::types::{ChunkId, Digest32, SYMBOL_SIZE};

use crate::chunk_store::ChunkStore;
use crate::progress::TransferProgress;
use crate::resume::ResumeState;
use crate::session::{Session, MAX_RETRIES};
use crate::transport::{C0Transport, D0Transport};

/// Per-IP auth failure rate limiter.
///
/// Tracks HMAC verification failures per source IP. After `max_failures` failures
/// within `window`, the IP is blocked for `block_duration`.
pub struct AuthRateLimiter {
    /// (failure timestamps, blocked_until)
    state: HashMap<IpAddr, (Vec<Instant>, Option<Instant>)>,
    max_failures: usize,
    window: Duration,
    block_duration: Duration,
}

impl AuthRateLimiter {
    pub fn new(max_failures: usize, window: Duration, block_duration: Duration) -> Self {
        Self {
            state: HashMap::new(),
            max_failures,
            window,
            block_duration,
        }
    }

    /// Check if an IP is currently blocked.
    pub fn is_blocked(&self, ip: &IpAddr) -> bool {
        if let Some((_, Some(until))) = self.state.get(ip) {
            Instant::now() < *until
        } else {
            false
        }
    }

    /// Record an auth failure from this IP. Returns true if the IP is now blocked.
    pub fn record_failure(&mut self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let (failures, blocked) = self.state.entry(ip).or_insert_with(|| (Vec::new(), None));

        // If already blocked, extend the block.
        if let Some(until) = blocked {
            if now < *until {
                return true;
            }
            // Block expired — reset.
            failures.clear();
            *blocked = None;
        }

        failures.push(now);
        // Evict failures outside the window.
        let cutoff = now - self.window;
        failures.retain(|t| *t > cutoff);

        if failures.len() >= self.max_failures {
            let block_until = now + self.block_duration;
            *blocked = Some(block_until);
            eprintln!(
                "rate-limiter: blocking {} for {}s after {} auth failures",
                ip,
                self.block_duration.as_secs(),
                self.max_failures,
            );
            true
        } else {
            false
        }
    }
}


/// Run the receiver state machine: wait for OFFER, send HAVE_ICT, decode SYM+MIX, COMMIT.
///
/// Returns the reassembled file data on success.
///
/// If `resume` is provided, verified chunks are persisted to disk as they are decoded.
/// On a subsequent run with the same resume directory, previously-decoded chunks are
/// loaded from disk and appear as "already have" in the ICT — reducing re-transfer.
/// After successful COMMIT, the resume state is cleaned up.
pub async fn run_receiver(
    session: &mut Session,
    c0: &mut C0Transport,
    d0: &D0Transport,
    base_data: Option<&[u8]>,
    resume: Option<&ResumeState>,
) -> std::io::Result<Vec<u8>> {
    let mut store = ChunkStore::new();

    // Load previously-decoded chunks from resume state, if any.
    if let Some(rs) = &resume {
        for (id, data) in rs.load_chunks()? {
            store.insert(id, data);
        }
    }

    let base_recipe = match base_data {
        Some(base) => {
            let base_chunks = chunker::chunk_fast(base);
            let meta: Vec<(ChunkId, usize)> = base_chunks.iter().map(|(id, d)| {
                store.insert(*id, d.clone());
                (*id, d.len())
            }).collect();
            Recipe::from_chunks(&meta)
        }
        None => Recipe { entries: vec![] },
    };
    let base_digest = base_recipe.digest();

    // --- R0: AwaitOffer ---
    let (target_recipe, h_target);
    let mut retries = 0u32;
    loop {
        let recv_result = tokio::time::timeout(session.control_timeout(), c0.recv_frame()).await;
        let (hdr, payload) = match recv_result {
            Err(_) if retries < MAX_RETRIES => {
                retries += 1;
                session.resend_unacked(c0).await?;
                continue;
            }
            Err(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!("timed out waiting for OFFER after {} retries", MAX_RETRIES),
                ));
            }
            Ok(result) => result?,
        };
        let frame = Frame::decode_payload(hdr.frame_type, &payload)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;

        match frame {
            Frame::Offer { h_target: ht, ops } => {
                // Apply ops to base_recipe to get target_recipe.
                let recipe = recipe_ops::apply(&base_recipe, &ops).map_err(|e| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
                })?;
                // Verify h_target matches.
                let computed = recipe.digest();
                if computed != ht {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "OFFER h_target does not match computed recipe digest",
                    ));
                }
                h_target = ht;
                target_recipe = recipe;

                // ACK the OFFER
                let ack = Frame::Ack {
                    ack_frame_id: hdr.frame_id,
                };
                session.send_control(c0, &ack, base_digest).await?;
                break;
            }
            Frame::Ack { ack_frame_id } => {
                session.record_ack(ack_frame_id);
                continue;
            }
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("expected OFFER, got {:?}", frame),
                ));
            }
        }
    }

    // Build ICT of chunks we already have (none for fresh receiver) vs target.
    let target_ids: HashSet<ChunkId> = target_recipe
        .entries
        .iter()
        .map(|e| e.chunk_id)
        .collect();
    let our_ids: HashSet<ChunkId> = store.keys().copied().collect();

    // Build difference ICT (target - have) for sender to peel directly.
    let have_count = our_ids.iter().filter(|id| target_ids.contains(id)).count();
    let d_est = target_ids.len().saturating_sub(have_count).max(1);
    let mut target_ict = Ict::with_estimated_missing(d_est);
    for id in &target_ids {
        target_ict.insert(id);
    }
    let mut our_ict = Ict::new(target_ict.m_log2);
    for id in &our_ids {
        if target_ids.contains(id) {
            our_ict.insert(id);
        }
    }

    // Receiver sends the difference ICT; sender peels it directly to recover missing set.
    let diff_ict = target_ict.subtract(&our_ict).map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
    })?;

    let have_ict = Frame::HaveIct {
        ict_data: diff_ict.encode_wire(),
    };
    session
        .send_control(c0, &have_ict, base_digest)
        .await?;

    // Compute expected missing digest for PLAN verification.
    // First appearance per ChunkId — matches sender's dedup rule.
    let mut seen_missing = HashSet::new();
    let missing_meta: Vec<(ChunkId, usize)> = target_recipe
        .entries
        .iter()
        .filter(|e| !our_ids.contains(&e.chunk_id) && seen_missing.insert(e.chunk_id))
        .map(|e| (e.chunk_id, e.chunk_len as usize))
        .collect();
    let expected_missing_recipe = Recipe::from_chunks(&missing_meta);
    let expected_missing_digest = expected_missing_recipe.digest();
    let total_missing_bytes: u64 = missing_meta.iter().map(|(_, len)| *len as u64).sum();

    // --- R1: ReceivingData ---
    // Wait for PLAN on C0.
    let n;
    let mut retries = 0u32;
    loop {
        let recv_result = tokio::time::timeout(session.control_timeout(), c0.recv_frame()).await;
        let (hdr, payload) = match recv_result {
            Err(_) if retries < MAX_RETRIES => {
                retries += 1;
                session.resend_unacked(c0).await?;
                continue;
            }
            Err(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!("timed out waiting for PLAN after {} retries", MAX_RETRIES),
                ));
            }
            Ok(result) => result?,
        };
        retries = 0;
        let frame = Frame::decode_payload(hdr.frame_type, &payload)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;

        match frame {
            Frame::Plan {
                l: _,
                ssx_profile: _,
                n: sym_count,
                missing_digest: md,
            } => {
                // Verify missing_digest matches our locally computed value.
                if md != expected_missing_digest {
                    let fork = Frame::Fork {
                        reason: 0x02,
                        expected: expected_missing_digest,
                        observed: md,
                    };
                    session.send_control(c0, &fork, base_digest).await?;
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "PLAN missing_digest mismatch: sender and receiver disagree on missing set",
                    ));
                }

                n = sym_count;

                // ACK the PLAN
                let ack = Frame::Ack {
                    ack_frame_id: hdr.frame_id,
                };
                session.send_control(c0, &ack, base_digest).await?;
                break;
            }
            Frame::IctFail { reason } => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("sender reported ICT peel failure, reason: 0x{:02x}", reason),
                ));
            }
            Frame::Ack { ack_frame_id } => {
                session.record_ack(ack_frame_id);
            }
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("expected PLAN, got {:?}", frame),
                ));
            }
        }
    }

    // Create decoder.
    let mut decoder = SsxDecoder::new(n as usize);
    let mut progress = TransferProgress::new("Recv", total_missing_bytes);
    let bytes_per_symbol = if n == 0 {
        0.0
    } else {
        total_missing_bytes as f64 / n as f64
    };

    // Receive SYM and MIX frames on D0, control frames on C0.
    // Bind D0 acceptance to C0 peer IP (TCP-authenticated) + session_id.
    let c0_peer_ip = c0.peer_addr()?.ip();
    let mut d0_deadline = tokio::time::Instant::now() + session.data_timeout();
    let mut d0_replay = ReplayWindow::new();
    let mut rate_limiter = AuthRateLimiter::new(5, Duration::from_secs(60), Duration::from_secs(300));

    // NEEDMORE tracking.
    let mut highest_mix_t: u32 = 0;
    let mut last_known_count: usize = 0;
    let mut needmore_sent: u32 = 0;
    const MAX_NEEDMORE: u32 = 3;
    const NEEDMORE_THRESHOLD: Duration = Duration::from_secs(5);
    let mut needmore_deadline = tokio::time::Instant::now() + NEEDMORE_THRESHOLD;

    loop {
        tokio::select! {
            result = d0.try_recv_frame() => {
                let (frame_result, maybe_addr) = result;
                let addr = match maybe_addr {
                    Some(a) => a,
                    None => {
                        // No addr means socket-level error (not datagram).
                        frame_result?;
                        continue;
                    }
                };
                // Rate limiter: check if source IP is blocked.
                if rate_limiter.is_blocked(&addr.ip()) {
                    continue;
                }
                let (hdr, payload) = match frame_result {
                    Ok(v) => v,
                    Err(e) => {
                        if e.kind() == std::io::ErrorKind::InvalidData {
                            rate_limiter.record_failure(addr.ip());
                        }
                        continue; // silently drop bad D0 frames
                    }
                };
                // Reject D0 frames from IPs other than the C0 peer.
                if addr.ip() != c0_peer_ip {
                    continue;
                }
                // Reject D0 frames with mismatched session_id.
                if hdr.session_id != session.params.session_id {
                    continue;
                }
                // Reject D0 frames with mismatched object_id / update_id / capsule_id.
                if hdr.object_id != session.params.object_id {
                    continue;
                }
                if hdr.update_id != session.params.update_id {
                    continue;
                }
                if hdr.capsule_id != session.params.capsule_id {
                    continue;
                }
                // Reject D0 frames with wrong base_digest.
                if hdr.base_digest != base_digest {
                    continue;
                }
                // Reject non-data-channel frames on D0.
                if hdr.chan != 1 {
                    continue;
                }
                // Replay protection: reject duplicate or too-old D0 frame_ids.
                if session.session_key().is_some() && !d0_replay.check_and_advance(hdr.frame_id) {
                    continue;
                }
                d0_deadline = tokio::time::Instant::now() + session.data_timeout();
                needmore_deadline = tokio::time::Instant::now() + NEEDMORE_THRESHOLD;
                let frame = Frame::decode_payload(hdr.frame_type, &payload)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;

                match frame {
                    Frame::Sym { k, data } => {
                        if data.len() >= SYMBOL_SIZE {
                            let mut sym = [0u8; SYMBOL_SIZE];
                            sym.copy_from_slice(&data[..SYMBOL_SIZE]);
                            decoder.add_sym(k as usize, sym);
                        } else {
                            let mut sym = [0u8; SYMBOL_SIZE];
                            sym[..data.len()].copy_from_slice(&data);
                            decoder.add_sym(k as usize, sym);
                        }
                    }
                    Frame::Mix { t, payload: mix_payload } => {
                        if mix_payload.len() >= SYMBOL_SIZE {
                            let mut sym = [0u8; SYMBOL_SIZE];
                            sym.copy_from_slice(&mix_payload[..SYMBOL_SIZE]);
                            decoder.add_mix(
                                t,
                                sym,
                                session.params.session_id,
                                session.params.object_id,
                                session.params.update_id,
                            );
                            if t > highest_mix_t {
                                highest_mix_t = t;
                            }
                        }
                    }
                    _ => {} // ignore unexpected data frames
                }
                // Track decoder progress for NEEDMORE.
                let current_known = decoder.known_count();
                if current_known > last_known_count {
                    last_known_count = current_known;
                    if bytes_per_symbol > 0.0 {
                        let done = (current_known as f64 * bytes_per_symbol).round() as u64;
                        progress.set(done);
                    }
                    needmore_sent = 0;
                    needmore_deadline = tokio::time::Instant::now() + NEEDMORE_THRESHOLD;
                }
            }
            result = c0.recv_frame() => {
                let (hdr, payload) = result?;
                let frame = Frame::decode_payload(hdr.frame_type, &payload)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;

                if let Frame::Ack { ack_frame_id } = frame {
                    session.record_ack(ack_frame_id);
                }
            }
            _ = tokio::time::sleep_until(needmore_deadline), if needmore_sent < MAX_NEEDMORE && last_known_count > 0 && !decoder.is_complete() => {
                let needmore = Frame::Needmore { next_t: highest_mix_t + 1 };
                session.send_control(c0, &needmore, base_digest).await?;
                needmore_sent += 1;
                d0_deadline = tokio::time::Instant::now() + session.data_timeout();
                needmore_deadline = tokio::time::Instant::now() + NEEDMORE_THRESHOLD;
            }
            _ = tokio::time::sleep_until(d0_deadline) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "D0 data reception timed out: no data-plane frames received",
                ));
            }
        }

        if decoder.is_complete() {
            progress.finish();
            break;
        }
    }

    // --- Decode complete: reconstruct chunks from symbols ---
    let symbols = decoder.take_symbols();

    // Reconstruct missing chunks from decoded symbols.
    // Symbols correspond to the deduped missing list (first appearance per ChunkId),
    // matching the sender's symbolization order.
    let mut seen_reassembly = HashSet::new();
    let missing_entries: Vec<_> = target_recipe
        .entries
        .iter()
        .filter(|e| !our_ids.contains(&e.chunk_id) && seen_reassembly.insert(e.chunk_id))
        .collect();

    // Map symbols back to chunks.
    let mut sym_idx = 0usize;
    for entry in &missing_entries {
        let chunk_len = entry.chunk_len as usize;
        let num_syms = if chunk_len == 0 {
            1
        } else {
            chunk_len.div_ceil(SYMBOL_SIZE)
        };

        let mut chunk_data = Vec::with_capacity(chunk_len);
        for s in 0..num_syms {
            let sym = symbols
                .get(&(sym_idx + s))
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("missing decoded symbol {}", sym_idx + s),
                    )
                })?;
            let remaining = chunk_len - chunk_data.len();
            let take = remaining.min(SYMBOL_SIZE);
            chunk_data.extend_from_slice(&sym[..take]);
        }
        sym_idx += num_syms;

        // Verify chunk hash.
        let computed_id = h128(&chunk_data);
        if computed_id != entry.chunk_id {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "chunk hash mismatch: expected {:?}, got {:?}",
                    entry.chunk_id, computed_id
                ),
            ));
        }
        // Persist to disk for resume if configured.
        if let Some(rs) = &resume {
            rs.save_chunk(&entry.chunk_id, &chunk_data)?;
        }
        store.insert(entry.chunk_id, chunk_data);
    }

    // Reassemble file from target recipe in order.
    let mut file_data = Vec::new();
    for entry in &target_recipe.entries {
        let chunk = store.get(&entry.chunk_id).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("missing chunk {:?} in store", entry.chunk_id),
            )
        })?;
        file_data.extend_from_slice(chunk);
    }

    // Send COMMIT.
    let commit = Frame::Commit { h_target };
    let commit_fid = session
        .send_control(c0, &commit, base_digest)
        .await?;

    // Wait for ACK of our commit (verify frame_id matches).
    let mut retries = 0u32;
    loop {
        let recv_result = tokio::time::timeout(session.control_timeout(), c0.recv_frame()).await;
        let (hdr, payload) = match recv_result {
            Err(_) if retries < MAX_RETRIES => {
                retries += 1;
                session.resend_unacked(c0).await?;
                continue;
            }
            Err(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!("timed out waiting for COMMIT ACK after {} retries", MAX_RETRIES),
                ));
            }
            Ok(result) => result?,
        };
        retries = 0;
        let frame = Frame::decode_payload(hdr.frame_type, &payload)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;

        if let Frame::Ack { ack_frame_id } = frame {
            session.record_ack(ack_frame_id);
            if ack_frame_id == commit_fid {
                break;
            }
        }
    }

    // Clean up resume state after successful transfer.
    if let Some(rs) = &resume {
        let _ = rs.cleanup();
    }

    Ok(file_data)
}

/// Build a manifest from a local directory for comparison.
fn build_local_manifest(dir: &Path) -> std::io::Result<Manifest> {
    let mut entries = Vec::new();
    walk_dir_manifest(dir, dir, &mut entries)?;
    entries.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(Manifest { entries })
}

fn walk_dir_manifest(
    base: &Path,
    dir: &Path,
    entries: &mut Vec<ManifestEntry>,
) -> std::io::Result<()> {
    if !dir.exists() {
        return Ok(());
    }
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            walk_dir_manifest(base, &path, entries)?;
        } else if path.is_file() {
            let rel = path
                .strip_prefix(base)
                .map_err(|e| std::io::Error::other(e.to_string()))?;
            let rel_str = rel.to_string_lossy().replace('\\', "/");
            let data = std::fs::read(&path)?;
            let chunks = chunker::chunk_fast(&data);
            let meta: Vec<(ChunkId, usize)> = chunks.iter().map(|(id, d)| (*id, d.len())).collect();
            let recipe = Recipe::from_chunks(&meta);
            let digest = recipe.digest();
            entries.push(ManifestEntry {
                path: rel_str,
                size: data.len() as u64,
                recipe_digest: digest,
            });
        }
    }
    Ok(())
}

/// Receive a directory tree from a remote sender.
///
/// Protocol: MANIFEST → MANIFEST_ACK → per-file OFFER/HAVE_ICT/PLAN/SYM+MIX/COMMIT.
pub async fn run_receiver_dir(
    session: &mut Session,
    c0: &mut C0Transport,
    d0: &D0Transport,
    out_dir: &Path,
) -> std::io::Result<()> {
    let base_digest = Digest32::default();

    // Wait for MANIFEST from sender.
    let sender_manifest: Manifest;
    let mut retries = 0u32;
    loop {
        let recv_result = tokio::time::timeout(session.control_timeout(), c0.recv_frame()).await;
        let (hdr, payload) = match recv_result {
            Err(_) if retries < MAX_RETRIES => {
                retries += 1;
                session.resend_unacked(c0).await?;
                continue;
            }
            Err(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "timed out waiting for MANIFEST",
                ));
            }
            Ok(result) => result?,
        };
        retries = 0;
        let frame = Frame::decode_payload(hdr.frame_type, &payload)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;

        match frame {
            Frame::Manifest { data } => {
                sender_manifest = Manifest::decode_wire(&data)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
                let ack = Frame::Ack { ack_frame_id: hdr.frame_id };
                session.send_control(c0, &ack, base_digest).await?;
                break;
            }
            Frame::Ack { ack_frame_id } => {
                session.record_ack(ack_frame_id);
                continue;
            }
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("expected MANIFEST, got {:?}", frame),
                ));
            }
        }
    }

    eprintln!("Received manifest: {} files", sender_manifest.entries.len());

    // Build local manifest and diff.
    let local_manifest = build_local_manifest(out_dir)?;
    let diff = local_manifest.diff(&sender_manifest);

    // Files we need: added + changed.
    let needed: Vec<&str> = diff
        .added
        .iter()
        .chain(diff.changed.iter().map(|(_, new)| new))
        .map(|e| e.path.as_str())
        .collect();

    eprintln!(
        "{} added, {} changed, {} unchanged, {} removed",
        diff.added.len(),
        diff.changed.len(),
        diff.unchanged.len(),
        diff.removed.len(),
    );

    // Send MANIFEST_ACK with needed file paths.
    let ack_frame = Frame::ManifestAck {
        files_needed: manifest::encode_paths_wire(&needed),
    };
    session.send_control(c0, &ack_frame, base_digest).await?;

    if needed.is_empty() {
        eprintln!("All files up to date.");
        return Ok(());
    }

    // Receive each needed file using the standard single-file protocol.
    // Increment update_id per file to match sender and distinguish D0 frames.
    std::fs::create_dir_all(out_dir)?;
    for (i, path) in needed.iter().enumerate() {
        session.params.update_id = (i + 1) as u64;
        eprintln!("[{}/{}] Receiving {}...", i + 1, needed.len(), path);
        let data = run_receiver(session, c0, d0, None, None).await?;
        let out_path = out_dir.join(path);
        if let Some(parent) = out_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&out_path, &data)?;
        eprintln!("  {} bytes -> {}", data.len(), out_path.display());
    }

    // Remove files that were deleted on sender side.
    for path in &diff.removed {
        let rm_path = out_dir.join(path);
        if rm_path.exists() {
            std::fs::remove_file(&rm_path)?;
            eprintln!("Removed: {}", path);
        }
    }

    eprintln!("Directory sync complete.");
    Ok(())
}
