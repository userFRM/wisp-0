use std::collections::HashSet;
use std::net::SocketAddr;

use wisp_core::chunker;
use wisp_core::frame::Frame;
use wisp_core::ict::Ict;
use wisp_core::recipe::Recipe;
use wisp_core::recipe_ops;
use wisp_core::ssx::{encode_mix, mix_indices, symbolize};
use wisp_core::types::{ChunkId, SYMBOL_SIZE};

use crate::chunk_store::ChunkStore;
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
    let chunks = chunker::chunk(data);
    let mut store = ChunkStore::new();
    let chunk_meta: Vec<(ChunkId, usize)> = chunks
        .iter()
        .map(|(id, d)| {
            store.insert(*id, d.clone());
            (*id, d.len())
        })
        .collect();

    let target_recipe = Recipe::from_chunks(&chunk_meta);
    let h_target = target_recipe.digest();

    let base_recipe = match base_data {
        Some(base) => {
            let base_chunks = chunker::chunk(base);
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
    let missing_chunks: Vec<(ChunkId, Vec<u8>)> = target_recipe
        .entries
        .iter()
        .filter(|e| missing_set.contains(&e.chunk_id) && seen.insert(e.chunk_id))
        .map(|e| {
            let data = store
                .get(&e.chunk_id)
                .expect("sender must have all chunks")
                .to_vec();
            (e.chunk_id, data)
        })
        .collect();

    let source_symbols = symbolize(&missing_chunks);
    let n = source_symbols.len() as u32;

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
                break;
            }
            Frame::Needmore { next_t } => {
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
