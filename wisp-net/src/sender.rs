use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::Path;

use wisp_core::chunker;
use wisp_core::frame::Frame;
use wisp_core::ict::Ict;
use wisp_core::manifest::{self, Manifest, ManifestEntry};
use wisp_core::recipe::Recipe;
use wisp_core::recipe_ops;
use wisp_core::ssx::{encode_mix, mix_indices, symbolize_ref};
use wisp_core::types::{ChunkId, Digest32, SYMBOL_SIZE};

use crate::progress::TransferProgress;
use crate::session::{Session, MAX_RETRIES};
use crate::transport::{C0Transport, D0Transport};

/// Run the sender state machine: chunk data, OFFER, wait for HAVE_ICT, stream SYM+MIX, wait for COMMIT.
pub async fn run_sender(
    session: &mut Session,
    c0: &mut C0Transport,
    d0: &D0Transport,
    peer_d0_addr: SocketAddr,
    data: &[u8],
    base_data: Option<&[u8]>,
) -> std::io::Result<()> {

    // --- Idle: chunk data, build recipe, send OFFER ---
    let chunks = chunker::chunk_fast_ref(data);
    let chunk_meta: Vec<(ChunkId, usize)> = chunks
        .iter()
        .map(|(id, d)| (*id, d.len()))
        .collect();
    let chunk_lookup: HashMap<ChunkId, &[u8]> = chunks
        .iter()
        .map(|(id, d)| (*id, *d))
        .collect();

    let target_recipe = Recipe::from_chunks(&chunk_meta);
    let h_target = target_recipe.digest();

    let base_recipe = match base_data {
        Some(base) => {
            let base_chunks = chunker::chunk_fast_ref(base);
            let meta: Vec<(ChunkId, usize)> = base_chunks.iter().map(|(id, d)| (*id, d.len())).collect();
            Recipe::from_chunks(&meta)
        }
        None => Recipe { entries: vec![] },
    };
    let base_digest = base_recipe.digest();
    let ops_data = recipe_ops::diff(&base_recipe, &target_recipe);

    let offer = Frame::Offer {
        h_target,
        ops: ops_data,
    };
    session.send_control(c0, &offer, base_digest).await?;

    // --- Offered: wait for HAVE_ICT ---
    let missing: Vec<ChunkId>;
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
                    format!("timed out waiting for HAVE_ICT after {} retries", MAX_RETRIES),
                ));
            }
            Ok(result) => result?,
        };
        retries = 0;
        let frame = Frame::decode_payload(hdr.frame_type, &payload)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;

        match frame {
            Frame::HaveIct { ict_data } => {
                let mut ict = Ict::decode_wire(&ict_data).map_err(|e| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
                })?;
                // Peel to find the missing set. On failure, send ICT_FAIL.
                missing = match ict.peel() {
                    Ok(keys) => keys,
                    Err(_) => {
                        let fail = Frame::IctFail { reason: 0x01 };
                        session.send_control(c0, &fail, base_digest).await?;
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "ICT peel failed (table undersized), sent ICT_FAIL to receiver",
                        ));
                    }
                };
                break;
            }
            Frame::Ack { ack_frame_id } => {
                session.record_ack(ack_frame_id);
                continue;
            }
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("unexpected frame in Offered state: {:?}", frame),
                ));
            }
        }
    }

    // --- Sending: build symbols from missing chunks, send PLAN, then SYM + MIX ---
    // Collect missing chunks in recipe order (first appearance per ChunkId).
    let missing_set: HashSet<ChunkId> = missing.iter().copied().collect();
    let mut seen = HashSet::new();
    let missing_chunks: Vec<(ChunkId, &[u8])> = target_recipe
        .entries
        .iter()
        .filter(|e| missing_set.contains(&e.chunk_id) && seen.insert(e.chunk_id))
        .map(|e| {
            let data = chunk_lookup
                .get(&e.chunk_id)
                .expect("sender must have all chunks");
            (e.chunk_id, *data)
        })
        .collect();

    let source_symbols = symbolize_ref(&missing_chunks);
    let n = source_symbols.len() as u32;
    let symbol_bytes = build_symbol_byte_lengths_ref(&missing_chunks);
    let total_missing_bytes: u64 = symbol_bytes.iter().map(|&b| b as u64).sum();
    let mut progress = TransferProgress::new("Send", total_missing_bytes);

    // Compute missing_digest: hash the wire-encoded recipe of missing chunks.
    let missing_meta: Vec<(ChunkId, usize)> = missing_chunks
        .iter()
        .map(|(id, d)| (*id, d.len()))
        .collect();
    let missing_recipe = Recipe::from_chunks(&missing_meta);
    let missing_digest = missing_recipe.digest();

    // Send PLAN
    let plan = Frame::Plan {
        l: SYMBOL_SIZE as u16,
        ssx_profile: 0,
        n,
        missing_digest,
    };
    session
        .send_control(c0, &plan, base_digest)
        .await?;

    // Send SYM frames for all source symbols.
    for (k, sym) in source_symbols.iter().enumerate() {
        let sym_frame = Frame::Sym {
            k: k as u32,
            data: sym.to_vec(),
        };
        session
            .send_data(d0, &sym_frame, base_digest, peer_d0_addr)
            .await?;
        if let Some(&len) = symbol_bytes.get(k) {
            progress.inc(len as u64);
        }
    }

    // Send MIX frames.
    let sym_refs: Vec<&[u8; SYMBOL_SIZE]> = source_symbols.iter().collect();
    let mut t: u32 = 0;
    let mix_count = n.max(4) * 2; // send 2x redundancy

    for _ in 0..mix_count {
        let (indices, _degree) = mix_indices(
            session.params.session_id,
            session.params.object_id,
            session.params.update_id,
            t,
            n,
        );
        let payload = encode_mix(&sym_refs, &indices);
        let mix_frame = Frame::Mix {
            t,
            payload: payload.to_vec(),
        };
        session
            .send_data(d0, &mix_frame, base_digest, peer_d0_addr)
            .await?;
        t += 1;
    }

    // --- Wait for COMMIT (or NEEDMORE) ---
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
                    format!("timed out waiting for COMMIT after {} retries", MAX_RETRIES),
                ));
            }
            Ok(result) => result?,
        };
        retries = 0;
        let frame = Frame::decode_payload(hdr.frame_type, &payload)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;

        match frame {
            Frame::Commit { h_target: commit_h } => {
                if commit_h != h_target {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "COMMIT h_target mismatch",
                    ));
                }
                // Send ACK for the commit frame_id.
                let ack = Frame::Ack {
                    ack_frame_id: hdr.frame_id,
                };
                session
                    .send_control(c0, &ack, base_digest)
                    .await?;
                progress.finish();
                break;
            }
            Frame::Needmore { next_t } => {
                // Loss signal: halve congestion window.
                session.cc.on_loss();
                // Send more MIX symbols starting from next_t.
                let start = next_t.max(t);
                for extra_t in start..start + n.max(4) {
                    let (indices, _) = mix_indices(
                        session.params.session_id,
                        session.params.object_id,
                        session.params.update_id,
                        extra_t,
                        n,
                    );
                    let payload = encode_mix(&sym_refs, &indices);
                    let mix_frame = Frame::Mix {
                        t: extra_t,
                        payload: payload.to_vec(),
                    };
                    session
                        .send_data(d0, &mix_frame, base_digest, peer_d0_addr)
                        .await?;
                }
                t = start + n.max(4);
            }
            Frame::Ack { ack_frame_id } => {
                session.record_ack(ack_frame_id);
            }
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("unexpected frame in Sending state: {:?}", frame),
                ));
            }
        }
    }

    Ok(())
}

/// Build a manifest from a directory by walking all files.
fn build_manifest_from_dir(dir: &Path) -> std::io::Result<(Manifest, HashMap<String, Vec<u8>>)> {
    let mut entries = Vec::new();
    let mut file_data = HashMap::new();
    walk_dir(dir, dir, &mut entries, &mut file_data)?;
    entries.sort_by(|a, b| a.path.cmp(&b.path));
    Ok((Manifest { entries }, file_data))
}

fn walk_dir(
    base: &Path,
    dir: &Path,
    entries: &mut Vec<ManifestEntry>,
    file_data: &mut HashMap<String, Vec<u8>>,
) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            walk_dir(base, &path, entries, file_data)?;
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
                path: rel_str.clone(),
                size: data.len() as u64,
                recipe_digest: digest,
            });
            file_data.insert(rel_str, data);
        }
    }
    Ok(())
}

/// Send a directory tree to a remote receiver.
///
/// Protocol: MANIFEST → MANIFEST_ACK → per-file OFFER/HAVE_ICT/PLAN/SYM+MIX/COMMIT.
pub async fn run_sender_dir(
    session: &mut Session,
    c0: &mut C0Transport,
    d0: &D0Transport,
    peer_d0_addr: SocketAddr,
    dir: &Path,
) -> std::io::Result<()> {
    let (sender_manifest, file_data) = build_manifest_from_dir(dir)?;
    eprintln!("Manifest: {} files", sender_manifest.entries.len());

    // Send MANIFEST on C0.
    let base_digest = Digest32::default();
    let manifest_frame = Frame::Manifest {
        data: sender_manifest.encode_wire(),
    };
    session.send_control(c0, &manifest_frame, base_digest).await?;

    // Wait for MANIFEST_ACK.
    let needed_paths: Vec<String>;
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
                    format!("timed out waiting for MANIFEST_ACK after {} retries", MAX_RETRIES),
                ));
            }
            Ok(result) => result?,
        };
        retries = 0;
        let frame = Frame::decode_payload(hdr.frame_type, &payload)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;

        match frame {
            Frame::ManifestAck { files_needed } => {
                needed_paths = manifest::decode_paths_wire(&files_needed)
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
                    format!("expected MANIFEST_ACK, got {:?}", frame),
                ));
            }
        }
    }

    eprintln!("{} files need syncing", needed_paths.len());
    if needed_paths.is_empty() {
        eprintln!("All files up to date.");
        return Ok(());
    }

    // Send each needed file using the standard single-file protocol.
    // Increment update_id per file so D0 frames are distinguishable.
    for (i, path) in needed_paths.iter().enumerate() {
        session.params.update_id = (i + 1) as u64;
        let data = file_data.get(path).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("receiver requested unknown file: {}", path),
            )
        })?;

        eprintln!("[{}/{}] Sending {} ({} bytes)...", i + 1, needed_paths.len(), path, data.len());
        run_sender(session, c0, d0, peer_d0_addr, data, None).await?;
    }

    eprintln!("Directory sync complete.");
    Ok(())
}

fn build_symbol_byte_lengths_ref(chunks: &[(ChunkId, &[u8])]) -> Vec<usize> {
    let mut lens = Vec::new();
    for (_, chunk_data) in chunks {
        if chunk_data.is_empty() {
            lens.push(0);
            continue;
        }
        let mut remaining = chunk_data.len();
        while remaining > 0 {
            let take = remaining.min(SYMBOL_SIZE);
            lens.push(take);
            remaining -= take;
        }
    }
    lens
}
