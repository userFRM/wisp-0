use std::net::SocketAddr;
use std::path::Path;

use wisp_core::frame::Frame;
use wisp_core::manifest::{ConflictPolicy, Manifest};
use wisp_core::types::Digest32;

use crate::receiver::run_receiver;
use crate::sender::run_sender;
use crate::session::{Session, MAX_RETRIES};
use crate::transport::{C0Transport, D0Transport};

/// Result of a bidirectional sync operation.
#[derive(Debug)]
pub struct SyncReport {
    /// Number of files sent to the peer.
    pub files_sent: usize,
    /// Number of files received from the peer.
    pub files_received: usize,
    /// Files that were skipped due to conflict policy.
    pub files_skipped: Vec<String>,
}

/// Compute what each side needs to send/receive.
///
/// Returns (initiator_sends, responder_sends, skipped).
/// - initiator_sends: paths the initiator should send to the responder
/// - responder_sends: paths the responder should send to the initiator
/// - skipped: paths skipped due to conflict policy
fn compute_sync_plan(
    initiator_manifest: &Manifest,
    responder_manifest: &Manifest,
    policy: ConflictPolicy,
) -> (Vec<String>, Vec<String>, Vec<String>) {
    let diff = responder_manifest.diff(initiator_manifest);

    // "added" in diff = files in initiator but not responder → initiator sends
    // "removed" in diff = files in responder but not initiator → responder sends
    // "changed" in diff = files in both with different digest → conflict

    let mut initiator_sends: Vec<String> = diff.added.iter().map(|e| e.path.clone()).collect();
    let mut responder_sends: Vec<String> = diff.removed.clone();
    let mut skipped = Vec::new();

    for (resp_entry, init_entry) in &diff.changed {
        match policy {
            ConflictPolicy::InitiatorWins => {
                initiator_sends.push(init_entry.path.clone());
            }
            ConflictPolicy::ResponderWins => {
                responder_sends.push(resp_entry.path.clone());
            }
            ConflictPolicy::Skip => {
                skipped.push(init_entry.path.clone());
            }
        }
    }

    initiator_sends.sort();
    responder_sends.sort();
    skipped.sort();

    (initiator_sends, responder_sends, skipped)
}

/// Run bidirectional sync as the initiator (connects to responder).
///
/// Protocol:
/// 1. Send SYNC_REQUEST with our manifest + D0 port
/// 2. Receive SYNC_RESPONSE with peer's manifest + D0 port
/// 3. Phase A: send files the responder needs
/// 4. Phase B: receive files we need from responder
pub async fn run_sync_initiator(
    session: &mut Session,
    c0: &mut C0Transport,
    d0: &D0Transport,
    local_dir: &Path,
    d0_local_port: u16,
    peer_ip: std::net::IpAddr,
    policy: ConflictPolicy,
) -> std::io::Result<SyncReport> {
    let base_digest = Digest32::default();

    // Build our manifest.
    let our_manifest = build_manifest(local_dir)?;
    let our_wire = our_manifest.encode_wire();

    // Send SYNC_REQUEST.
    let req = Frame::SyncRequest {
        d0_port: d0_local_port,
        manifest_data: our_wire,
    };
    session.send_control(c0, &req, base_digest).await?;

    // Wait for SYNC_RESPONSE.
    let peer_manifest: Manifest;
    let peer_d0_port: u16;
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
                    "timed out waiting for SYNC_RESPONSE",
                ));
            }
            Ok(result) => result?,
        };
        retries = 0;
        let frame = Frame::decode_payload(hdr.frame_type, &payload)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;

        match frame {
            Frame::SyncResponse { d0_port, manifest_data } => {
                peer_d0_port = d0_port;
                peer_manifest = Manifest::decode_wire(&manifest_data)
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
                    format!("expected SYNC_RESPONSE, got {:?}", frame),
                ));
            }
        }
    }

    let peer_d0_addr = SocketAddr::new(peer_ip, peer_d0_port);
    let (initiator_sends, responder_sends, skipped) =
        compute_sync_plan(&our_manifest, &peer_manifest, policy);

    eprintln!(
        "Sync plan: send {}, receive {}, skip {}",
        initiator_sends.len(),
        responder_sends.len(),
        skipped.len(),
    );

    // Phase A: send files the responder needs.
    let file_data = read_files(local_dir, &initiator_sends)?;
    for (i, path) in initiator_sends.iter().enumerate() {
        session.params.update_id = (i + 1) as u64;
        let data = &file_data[i];
        eprintln!("[send {}/{}] {} ({} bytes)", i + 1, initiator_sends.len(), path, data.len());
        run_sender(session, c0, d0, peer_d0_addr, data, None).await?;
    }

    // Phase B: receive files we need from responder.
    std::fs::create_dir_all(local_dir)?;
    for (i, path) in responder_sends.iter().enumerate() {
        session.params.update_id = (initiator_sends.len() + i + 1) as u64;
        eprintln!("[recv {}/{}] {}", i + 1, responder_sends.len(), path);
        let data = run_receiver(session, c0, d0, None, None).await?;
        let out_path = local_dir.join(path);
        if let Some(parent) = out_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&out_path, &data)?;
    }

    eprintln!("Sync complete.");

    Ok(SyncReport {
        files_sent: initiator_sends.len(),
        files_received: responder_sends.len(),
        files_skipped: skipped,
    })
}

/// Run bidirectional sync as the responder (accepts connection).
///
/// Protocol:
/// 1. Receive SYNC_REQUEST with peer's manifest + D0 port
/// 2. Send SYNC_RESPONSE with our manifest + D0 port
/// 3. Phase A: receive files from initiator
/// 4. Phase B: send files the initiator needs
pub async fn run_sync_responder(
    session: &mut Session,
    c0: &mut C0Transport,
    d0: &D0Transport,
    local_dir: &Path,
    d0_local_port: u16,
    peer_ip: std::net::IpAddr,
    policy: ConflictPolicy,
) -> std::io::Result<SyncReport> {
    let base_digest = Digest32::default();

    // Wait for SYNC_REQUEST.
    let peer_manifest: Manifest;
    let peer_d0_port: u16;
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
                    "timed out waiting for SYNC_REQUEST",
                ));
            }
            Ok(result) => result?,
        };
        retries = 0;
        let frame = Frame::decode_payload(hdr.frame_type, &payload)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;

        match frame {
            Frame::SyncRequest { d0_port, manifest_data } => {
                peer_d0_port = d0_port;
                peer_manifest = Manifest::decode_wire(&manifest_data)
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
                    format!("expected SYNC_REQUEST, got {:?}", frame),
                ));
            }
        }
    }

    // Build our manifest and send SYNC_RESPONSE.
    let our_manifest = build_manifest(local_dir)?;
    let our_wire = our_manifest.encode_wire();

    let resp = Frame::SyncResponse {
        d0_port: d0_local_port,
        manifest_data: our_wire,
    };
    session.send_control(c0, &resp, base_digest).await?;

    // Wait for ACK of our SYNC_RESPONSE before proceeding.
    // Without this, the responder may return (0 files) and drop the TCP
    // connection before the initiator can send back its ACK → BrokenPipe.
    let resp_fid = session.last_sent_frame_id();
    let mut retries = 0u32;
    loop {
        let recv_result = tokio::time::timeout(session.control_timeout(), c0.recv_frame()).await;
        let (hdr, payload) = match recv_result {
            Err(_) if retries < MAX_RETRIES => {
                retries += 1;
                session.resend_unacked(c0).await?;
                continue;
            }
            Err(_) => break, // give up waiting, proceed anyway
            Ok(result) => result?,
        };
        retries = 0;
        let frame = Frame::decode_payload(hdr.frame_type, &payload)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
        match frame {
            Frame::Ack { ack_frame_id } => {
                session.record_ack(ack_frame_id);
                if ack_frame_id == resp_fid {
                    break;
                }
            }
            _ => continue,
        }
    }

    let peer_d0_addr = SocketAddr::new(peer_ip, peer_d0_port);
    let (initiator_sends, responder_sends, skipped) =
        compute_sync_plan(&peer_manifest, &our_manifest, policy);

    eprintln!(
        "Sync plan: receive {}, send {}, skip {}",
        initiator_sends.len(),
        responder_sends.len(),
        skipped.len(),
    );

    // Phase A: receive files from initiator.
    std::fs::create_dir_all(local_dir)?;
    for (i, path) in initiator_sends.iter().enumerate() {
        session.params.update_id = (i + 1) as u64;
        eprintln!("[recv {}/{}] {}", i + 1, initiator_sends.len(), path);
        let data = run_receiver(session, c0, d0, None, None).await?;
        let out_path = local_dir.join(path);
        if let Some(parent) = out_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&out_path, &data)?;
    }

    // Phase B: send files the initiator needs.
    let file_data = read_files(local_dir, &responder_sends)?;
    for (i, path) in responder_sends.iter().enumerate() {
        session.params.update_id = (initiator_sends.len() + i + 1) as u64;
        let data = &file_data[i];
        eprintln!("[send {}/{}] {} ({} bytes)", i + 1, responder_sends.len(), path, data.len());
        run_sender(session, c0, d0, peer_d0_addr, data, None).await?;
    }

    eprintln!("Sync complete.");

    Ok(SyncReport {
        files_sent: responder_sends.len(),
        files_received: initiator_sends.len(),
        files_skipped: skipped,
    })
}

/// Build a manifest from a local directory.
fn build_manifest(dir: &Path) -> std::io::Result<Manifest> {
    let mut entries = Vec::new();
    walk_dir(dir, dir, &mut entries)?;
    entries.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(Manifest { entries })
}

fn walk_dir(
    base: &Path,
    dir: &Path,
    entries: &mut Vec<wisp_core::manifest::ManifestEntry>,
) -> std::io::Result<()> {
    if !dir.exists() {
        return Ok(());
    }
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            walk_dir(base, &path, entries)?;
        } else if path.is_file() {
            let rel = path
                .strip_prefix(base)
                .map_err(|e| std::io::Error::other(e.to_string()))?;
            let rel_str = rel.to_string_lossy().replace('\\', "/");
            let data = std::fs::read(&path)?;
            let chunks = wisp_core::chunker::chunk_fast(&data);
            let meta: Vec<(wisp_core::types::ChunkId, usize)> =
                chunks.iter().map(|(id, d)| (*id, d.len())).collect();
            let recipe = wisp_core::recipe::Recipe::from_chunks(&meta);
            let digest = recipe.digest();
            entries.push(wisp_core::manifest::ManifestEntry {
                path: rel_str,
                size: data.len() as u64,
                recipe_digest: digest,
            });
        }
    }
    Ok(())
}

/// Read file contents for a list of relative paths.
fn read_files(dir: &Path, paths: &[String]) -> std::io::Result<Vec<Vec<u8>>> {
    paths
        .iter()
        .map(|p| std::fs::read(dir.join(p)))
        .collect()
}
