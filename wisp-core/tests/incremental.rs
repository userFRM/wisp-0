//! Incremental sync test: Version 1 -> Version 2 delta sync.
//! Verifies that only new/changed chunks are transferred.

use std::collections::{HashMap, HashSet};
use wisp_core::hashbrown::HashMap as HbHashMap;

use wisp_core::chunk_id::h128;
use wisp_core::chunker;
use wisp_core::ict::Ict;
use wisp_core::recipe::Recipe;
use wisp_core::recipe_ops;
use wisp_core::ssx::{encode_mix, mix_indices, symbolize};
use wisp_core::ssx_decoder::SsxDecoder;
use wisp_core::types::{ChunkId, SYMBOL_SIZE};

/// Generate deterministic pseudo-random data.
fn generate_test_data(size: usize, seed: u64) -> Vec<u8> {
    let mut data = Vec::with_capacity(size);
    let mut state = seed;
    for _ in 0..size {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        data.push((state >> 33) as u8);
    }
    data
}

/// Compute the missing list in recipe order (first appearance of each missing chunk_id).
fn compute_missing_list(
    target_recipe: &Recipe,
    missing_keys: &HashSet<ChunkId>,
) -> Vec<(ChunkId, u64)> {
    let mut seen = HashSet::new();
    let mut list = Vec::new();
    for entry in &target_recipe.entries {
        if missing_keys.contains(&entry.chunk_id) && seen.insert(entry.chunk_id) {
            list.push((entry.chunk_id, entry.chunk_len));
        }
    }
    list
}

/// Reconstruct chunks from decoded symbols given a missing list.
fn reconstruct_chunks(
    missing_list: &[(ChunkId, u64)],
    symbols: &HbHashMap<usize, Box<[u8; SYMBOL_SIZE]>>,
) -> HashMap<ChunkId, Vec<u8>> {
    let mut result = HashMap::new();
    let mut sym_off = 0;
    for (chunk_id, chunk_len) in missing_list {
        let len = *chunk_len as usize;
        let num_syms = if len == 0 { 1 } else { (len + SYMBOL_SIZE - 1) / SYMBOL_SIZE };
        let mut chunk_bytes = Vec::with_capacity(len);
        for s in 0..num_syms {
            chunk_bytes.extend_from_slice(symbols[&(sym_off + s)].as_ref());
        }
        chunk_bytes.truncate(len);
        result.insert(*chunk_id, chunk_bytes);
        sym_off += num_syms;
    }
    result
}

#[test]
fn incremental_v1_to_v2_delta_sync() {
    // --- Version 1 ---
    let file_v1 = generate_test_data(200_000, 42);
    let chunks_v1 = chunker::chunk(&file_v1);
    let chunk_meta_v1: Vec<(ChunkId, usize)> =
        chunks_v1.iter().map(|(id, data)| (*id, data.len())).collect();
    let recipe_v1 = Recipe::from_chunks(&chunk_meta_v1);

    // --- Version 2: modify the middle portion ---
    let mut file_v2 = file_v1.clone();
    // Overwrite a region in the middle to create different chunks there.
    let modify_start = 80_000;
    let modify_end = 120_000;
    for i in modify_start..modify_end {
        file_v2[i] = file_v2[i].wrapping_add(0x5A);
    }
    // Also append some new data.
    let extra = generate_test_data(30_000, 999);
    file_v2.extend_from_slice(&extra);

    let chunks_v2 = chunker::chunk(&file_v2);
    let chunk_meta_v2: Vec<(ChunkId, usize)> =
        chunks_v2.iter().map(|(id, data)| (*id, data.len())).collect();
    let recipe_v2 = Recipe::from_chunks(&chunk_meta_v2);

    // Verify v1 and v2 have different digests.
    assert_ne!(recipe_v1.digest(), recipe_v2.digest(), "v1 and v2 must differ");

    // --- Sender: compute RecipeOps from v1 to v2 ---
    let ops_data = recipe_ops::diff(&recipe_v1, &recipe_v2);

    // --- Receiver: apply ops to get target recipe ---
    let receiver_target = recipe_ops::apply(&recipe_v1, &ops_data).unwrap();
    assert_eq!(receiver_target, recipe_v2, "apply must reproduce v2 recipe");

    // --- Receiver: compute missing keys ---
    let target_keys: HashSet<ChunkId> = recipe_v2.entries.iter().map(|e| e.chunk_id).collect();
    let have_keys: HashSet<ChunkId> = recipe_v1.entries.iter().map(|e| e.chunk_id).collect();
    let missing_keys: HashSet<ChunkId> = target_keys.difference(&have_keys).copied().collect();

    // Some chunks should be shared (not all are missing).
    let shared_count = target_keys.intersection(&have_keys).count();
    assert!(
        shared_count > 0,
        "incremental sync should have shared chunks, got 0"
    );
    assert!(
        !missing_keys.is_empty(),
        "there should be new/changed chunks to transfer"
    );
    assert!(
        missing_keys.len() < target_keys.len(),
        "not all chunks should be missing (delta sync should reuse v1 chunks). \
         Missing: {}, Total: {}",
        missing_keys.len(),
        target_keys.len()
    );

    // --- ICT reconciliation ---
    let d_est = missing_keys.len();
    let mut sender_ict = Ict::with_estimated_missing(d_est);
    for entry in &recipe_v2.entries {
        sender_ict.insert(&entry.chunk_id);
    }

    // Receiver inserts keys it has that are also in target.
    let mut receiver_ict = Ict::new(sender_ict.m_log2);
    let have_in_target: HashSet<ChunkId> = have_keys.intersection(&target_keys).copied().collect();
    for key in &have_in_target {
        receiver_ict.insert(key);
    }

    let mut diff_ict = sender_ict.subtract(&receiver_ict).unwrap();
    let peeled = diff_ict.peel().unwrap();
    let peeled_set: HashSet<ChunkId> = peeled.iter().copied().collect();
    assert_eq!(peeled_set, missing_keys, "peel must recover exactly the missing set");

    // --- Symbolize only missing chunks ---
    let missing_list = compute_missing_list(&recipe_v2, &missing_keys);

    let chunk_data_v2: HashMap<ChunkId, &Vec<u8>> =
        chunks_v2.iter().map(|(id, data)| (*id, data)).collect();
    let missing_chunks: Vec<(ChunkId, Vec<u8>)> = missing_list
        .iter()
        .map(|(id, _)| (*id, chunk_data_v2[id].clone()))
        .collect();

    let source_symbols = symbolize(&missing_chunks);
    let n = source_symbols.len();

    // --- Decode: SYM + MIX ---
    let mut decoder = SsxDecoder::new(n);

    // Feed all as SYM.
    for (i, sym) in source_symbols.iter().enumerate() {
        decoder.add_sym(i, *sym);
    }
    assert!(decoder.is_complete());

    let recovered_symbols = decoder.take_symbols();
    let new_chunks = reconstruct_chunks(&missing_list, &recovered_symbols);

    // Verify each new chunk's hash.
    for (chunk_id, chunk_bytes) in &new_chunks {
        assert_eq!(
            h128(chunk_bytes),
            *chunk_id,
            "reconstructed chunk hash must match chunk_id"
        );
    }

    // --- Reassemble v2 from have_chunks (v1) + new_chunks ---
    let have_chunk_data: HashMap<ChunkId, &Vec<u8>> =
        chunks_v1.iter().map(|(id, data)| (*id, data)).collect();

    let mut final_data = Vec::with_capacity(file_v2.len());
    for entry in &recipe_v2.entries {
        if let Some(data) = new_chunks.get(&entry.chunk_id) {
            final_data.extend_from_slice(data);
        } else if let Some(data) = have_chunk_data.get(&entry.chunk_id) {
            final_data.extend_from_slice(data);
        } else {
            panic!(
                "chunk {:?} not found in new or existing chunks",
                entry.chunk_id
            );
        }
    }

    assert_eq!(final_data.len(), file_v2.len(), "v2 length must match");
    assert_eq!(final_data, file_v2, "v2 byte-for-byte match required");
}

#[test]
fn incremental_with_mix_recovery() {
    // Same incremental flow but uses MIX symbols for missing chunk recovery.
    let file_v1 = generate_test_data(100_000, 7);
    let chunks_v1 = chunker::chunk(&file_v1);
    let chunk_meta_v1: Vec<(ChunkId, usize)> =
        chunks_v1.iter().map(|(id, data)| (*id, data.len())).collect();
    let recipe_v1 = Recipe::from_chunks(&chunk_meta_v1);

    // Version 2: append data.
    let mut file_v2 = file_v1.clone();
    file_v2.extend_from_slice(&generate_test_data(50_000, 333));

    let chunks_v2 = chunker::chunk(&file_v2);
    let chunk_meta_v2: Vec<(ChunkId, usize)> =
        chunks_v2.iter().map(|(id, data)| (*id, data.len())).collect();
    let recipe_v2 = Recipe::from_chunks(&chunk_meta_v2);

    let ops_data = recipe_ops::diff(&recipe_v1, &recipe_v2);
    let receiver_target = recipe_ops::apply(&recipe_v1, &ops_data).unwrap();
    assert_eq!(receiver_target, recipe_v2);

    let target_keys: HashSet<ChunkId> = recipe_v2.entries.iter().map(|e| e.chunk_id).collect();
    let have_keys: HashSet<ChunkId> = recipe_v1.entries.iter().map(|e| e.chunk_id).collect();
    let missing_keys: HashSet<ChunkId> = target_keys.difference(&have_keys).copied().collect();

    if missing_keys.is_empty() {
        // Trivial case: no new chunks (all content was already in v1 chunks).
        // Just verify recipe reassembly works.
        let have_chunk_data: HashMap<ChunkId, &Vec<u8>> =
            chunks_v1.iter().map(|(id, data)| (*id, data)).collect();
        let mut final_data = Vec::new();
        for entry in &recipe_v2.entries {
            final_data.extend_from_slice(have_chunk_data[&entry.chunk_id]);
        }
        assert_eq!(final_data, file_v2);
        return;
    }

    let missing_list = compute_missing_list(&recipe_v2, &missing_keys);
    let chunk_data_v2: HashMap<ChunkId, &Vec<u8>> =
        chunks_v2.iter().map(|(id, data)| (*id, data)).collect();
    let missing_chunks: Vec<(ChunkId, Vec<u8>)> = missing_list
        .iter()
        .map(|(id, _)| (*id, chunk_data_v2[id].clone()))
        .collect();

    let source_symbols = symbolize(&missing_chunks);
    let n = source_symbols.len();
    let sym_refs: Vec<&[u8; SYMBOL_SIZE]> = source_symbols.iter().collect();

    let session_id: u64 = 50;
    let object_id: u64 = 60;
    let update_id: u64 = 70;

    let mut decoder = SsxDecoder::new(n);

    // Feed first quarter as SYM.
    let sym_count = (n / 4).max(1);
    for i in 0..sym_count.min(n) {
        decoder.add_sym(i, source_symbols[i]);
    }

    // Feed MIX until complete.
    for t in 0..3000u32 {
        if decoder.is_complete() {
            break;
        }
        let (indices, _) = mix_indices(session_id, object_id, update_id, t, n as u32);
        let payload = encode_mix(&sym_refs, &indices);
        decoder.add_mix(t, payload, session_id, object_id, update_id);
    }

    assert!(
        decoder.is_complete(),
        "MIX recovery must complete. Known: {}/{}",
        decoder.known_count(),
        n
    );

    let recovered_symbols = decoder.take_symbols();
    let new_chunks = reconstruct_chunks(&missing_list, &recovered_symbols);

    // Reassemble v2.
    let have_chunk_data: HashMap<ChunkId, &Vec<u8>> =
        chunks_v1.iter().map(|(id, data)| (*id, data)).collect();
    let mut final_data = Vec::new();
    for entry in &recipe_v2.entries {
        if let Some(data) = new_chunks.get(&entry.chunk_id) {
            final_data.extend_from_slice(data);
        } else if let Some(data) = have_chunk_data.get(&entry.chunk_id) {
            final_data.extend_from_slice(data);
        } else {
            panic!("chunk {:?} missing from both sources", entry.chunk_id);
        }
    }
    assert_eq!(final_data, file_v2, "v2 byte-for-byte match with MIX recovery");
}

#[test]
fn incremental_no_change_identity() {
    // Edge case: v1 == v2, no chunks missing.
    let file = generate_test_data(80_000, 55);
    let chunks = chunker::chunk(&file);
    let chunk_meta: Vec<(ChunkId, usize)> = chunks.iter().map(|(id, data)| (*id, data.len())).collect();
    let recipe = Recipe::from_chunks(&chunk_meta);

    let ops_data = recipe_ops::diff(&recipe, &recipe);
    let target = recipe_ops::apply(&recipe, &ops_data).unwrap();
    assert_eq!(target, recipe);

    let target_keys: HashSet<ChunkId> = recipe.entries.iter().map(|e| e.chunk_id).collect();
    let have_keys: HashSet<ChunkId> = recipe.entries.iter().map(|e| e.chunk_id).collect();
    let missing_keys: HashSet<ChunkId> = target_keys.difference(&have_keys).copied().collect();
    assert!(missing_keys.is_empty(), "no chunks should be missing when v1 == v2");

    // Reassemble from existing chunks.
    let chunk_data: HashMap<ChunkId, &Vec<u8>> =
        chunks.iter().map(|(id, data)| (*id, data)).collect();
    let mut final_data = Vec::new();
    for entry in &recipe.entries {
        final_data.extend_from_slice(chunk_data[&entry.chunk_id]);
    }
    assert_eq!(final_data, file, "identity sync must reproduce original");
}
