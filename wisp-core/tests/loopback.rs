//! Full OFFER->COMMIT loopback test: exercises the complete protocol flow in-process.

use std::collections::{HashMap, HashSet};

use wisp_core::chunk_id::{h128, h256};
use wisp_core::chunker;
use wisp_core::ict::Ict;
use wisp_core::recipe::Recipe;
use wisp_core::recipe_ops;
use wisp_core::ssx::{encode_mix, mix_indices, symbolize};
use wisp_core::ssx_decoder::SsxDecoder;
use wisp_core::types::{ChunkId, SYMBOL_SIZE};
use wisp_core::varint;

/// Generate ~200KB of deterministic pseudo-random data.
fn generate_test_data(size: usize, seed: u64) -> Vec<u8> {
    let mut data = Vec::with_capacity(size);
    let mut state = seed;
    for _ in 0..size {
        // Simple LCG for determinism.
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        data.push((state >> 33) as u8);
    }
    data
}

/// Encode MissingWire from a missing list of (chunk_id, chunk_len) pairs.
fn encode_missing_wire(missing_list: &[(ChunkId, u64)]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(0u8); // version = 0
    varint::encode_vec(missing_list.len() as u64, &mut buf);
    for (chunk_id, chunk_len) in missing_list {
        buf.extend_from_slice(&chunk_id.0);
        varint::encode_vec(*chunk_len, &mut buf);
    }
    buf
}

/// Compute the missing list: scan target_recipe in order, emit (chunk_id, chunk_len) on first
/// appearance if the chunk_id is in missing_keys.
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

#[test]
fn loopback_full_offer_commit_empty_base() {
    // --- Step 1: Generate deterministic data and chunk it ---
    let original_data = generate_test_data(200_000, 42);
    let chunks = chunker::chunk(&original_data);
    assert!(!chunks.is_empty(), "chunker should produce at least one chunk");

    // Verify chunking is correct: concatenation equals original.
    let reassembled_from_chunks: Vec<u8> = chunks.iter().flat_map(|c| c.1.iter().copied()).collect();
    assert_eq!(reassembled_from_chunks, original_data);

    // --- Step 2: Build target Recipe and compute H_target ---
    let chunk_meta: Vec<(ChunkId, usize)> = chunks.iter().map(|(id, data)| (*id, data.len())).collect();
    let target_recipe = Recipe::from_chunks(&chunk_meta);
    let h_target = target_recipe.digest();

    // Verify recipe wire round-trip.
    let wire = target_recipe.encode_wire();
    let decoded_recipe = Recipe::decode_wire(&wire).unwrap();
    assert_eq!(decoded_recipe, target_recipe);
    assert_eq!(decoded_recipe.digest(), h_target);

    // --- Step 3: Empty base (first sync) ---
    let base_recipe = Recipe { entries: vec![] };
    let ops_data = recipe_ops::diff(&base_recipe, &target_recipe);
    let receiver_target = recipe_ops::apply(&base_recipe, &ops_data).unwrap();
    assert_eq!(receiver_target, target_recipe, "apply(empty, ops) must recover target");

    // All chunks are missing since receiver has nothing.
    let target_keys: HashSet<ChunkId> = target_recipe.entries.iter().map(|e| e.chunk_id).collect();
    let have_keys: HashSet<ChunkId> = HashSet::new(); // empty base
    let missing_keys: HashSet<ChunkId> = target_keys.difference(&have_keys).copied().collect();
    assert_eq!(missing_keys, target_keys, "all keys should be missing on first sync");

    // --- Step 4: Build ICTs, subtract, peel ---
    let d_est = missing_keys.len();
    let mut sender_ict = Ict::with_estimated_missing(d_est);
    for entry in &target_recipe.entries {
        sender_ict.insert(&entry.chunk_id);
    }

    // Receiver ICT is empty (have_keys is empty, intersection with target is empty).
    let receiver_ict = Ict::new(sender_ict.m_log2);

    let mut diff_ict = sender_ict.subtract(&receiver_ict).unwrap();
    let peeled = diff_ict.peel().unwrap();

    // Peeled set should contain exactly the unique target keys.
    let peeled_set: HashSet<ChunkId> = peeled.iter().copied().collect();
    assert_eq!(peeled_set, target_keys, "peel must recover all missing chunk_ids");

    // --- Step 5: Symbolize missing chunks and build MissingWire ---
    // Build missing list in recipe order (first appearance).
    let missing_list = compute_missing_list(&target_recipe, &missing_keys);

    // Build chunk data lookup.
    let chunk_data_map: HashMap<ChunkId, &Vec<u8>> = chunks.iter().map(|(id, data)| (*id, data)).collect();

    // Build ordered missing chunks for symbolization.
    let missing_chunks: Vec<(ChunkId, Vec<u8>)> = missing_list
        .iter()
        .map(|(id, _len)| (*id, chunk_data_map[id].clone()))
        .collect();

    let source_symbols = symbolize(&missing_chunks);
    let n = source_symbols.len();
    assert!(n > 0, "must have at least one source symbol");

    // Verify symbol count: each chunk produces ceil(chunk_len / 1024) symbols.
    let expected_n: usize = missing_chunks
        .iter()
        .map(|(_, data)| {
            if data.is_empty() {
                1
            } else {
                (data.len() + SYMBOL_SIZE - 1) / SYMBOL_SIZE
            }
        })
        .sum();
    assert_eq!(n, expected_n, "symbol count must match ceil(chunk_len/1024) per chunk");

    // Build MissingWire and compute missing_digest.
    let missing_wire = encode_missing_wire(&missing_list);
    let missing_digest = h256(&missing_wire);
    // Deterministic: same inputs produce same digest.
    assert_eq!(h256(&encode_missing_wire(&missing_list)), missing_digest);

    // --- Step 6: Feed SYM + MIX to SsxDecoder ---
    let mut decoder = SsxDecoder::new(n);

    // Feed all source symbols directly (SYM frames).
    for (i, sym) in source_symbols.iter().enumerate() {
        decoder.add_sym(i, *sym);
    }
    assert!(
        decoder.is_complete(),
        "decoder should be complete after all SYM frames. Known: {}/{}",
        decoder.known_count(),
        n
    );

    // --- Step 7: Reassemble chunks from symbols ---
    let recovered_symbols = decoder.take_symbols();

    // Reconstruct each chunk: concatenate symbols, truncate to chunk_len.
    let mut sym_offset = 0;
    for (chunk_id, chunk_len) in &missing_list {
        let num_syms = if (*chunk_len as usize) == 0 {
            1
        } else {
            (*chunk_len as usize + SYMBOL_SIZE - 1) / SYMBOL_SIZE
        };

        let mut chunk_bytes = Vec::with_capacity(*chunk_len as usize);
        for s in 0..num_syms {
            let sym = recovered_symbols
                .get(&(sym_offset + s))
                .expect("symbol must exist");
            chunk_bytes.extend_from_slice(sym.as_ref());
        }
        chunk_bytes.truncate(*chunk_len as usize);

        // Verify H128(chunk_bytes) == chunk_id.
        let computed_id = h128(&chunk_bytes);
        assert_eq!(
            computed_id, *chunk_id,
            "chunk hash mismatch after reconstruction"
        );

        sym_offset += num_syms;
    }
    assert_eq!(sym_offset, n, "all symbols must be consumed");

    // --- Step 8: Reassemble full file from recipe order ---
    // Build a map from chunk_id to reconstructed bytes.
    let mut reconstructed_chunks: HashMap<ChunkId, Vec<u8>> = HashMap::new();
    let mut sym_off = 0;
    for (chunk_id, chunk_len) in &missing_list {
        let num_syms = if (*chunk_len as usize) == 0 {
            1
        } else {
            (*chunk_len as usize + SYMBOL_SIZE - 1) / SYMBOL_SIZE
        };

        let mut chunk_bytes = Vec::with_capacity(*chunk_len as usize);
        for s in 0..num_syms {
            let sym = recovered_symbols
                .get(&(sym_off + s))
                .expect("symbol must exist");
            chunk_bytes.extend_from_slice(sym.as_ref());
        }
        chunk_bytes.truncate(*chunk_len as usize);
        reconstructed_chunks.insert(*chunk_id, chunk_bytes);
        sym_off += num_syms;
    }

    // Reassemble in recipe order.
    let mut final_data = Vec::with_capacity(original_data.len());
    for entry in &target_recipe.entries {
        let chunk_bytes = reconstructed_chunks
            .get(&entry.chunk_id)
            .expect("every chunk_id in recipe must have data");
        final_data.extend_from_slice(chunk_bytes);
    }

    assert_eq!(
        final_data.len(),
        original_data.len(),
        "reconstructed file length must match"
    );
    assert_eq!(final_data, original_data, "byte-for-byte match required");
}

#[test]
fn loopback_with_mix_symbols() {
    // Same as above but feeds MIX symbols too, verifying the fountain decoder path.
    let original_data = generate_test_data(50_000, 99);
    let chunks = chunker::chunk(&original_data);
    let chunk_meta: Vec<(ChunkId, usize)> = chunks.iter().map(|(id, data)| (*id, data.len())).collect();
    let target_recipe = Recipe::from_chunks(&chunk_meta);

    let target_keys: HashSet<ChunkId> = target_recipe.entries.iter().map(|e| e.chunk_id).collect();
    let missing_list = compute_missing_list(&target_recipe, &target_keys);

    let chunk_data_map: HashMap<ChunkId, &Vec<u8>> = chunks.iter().map(|(id, data)| (*id, data)).collect();
    let missing_chunks: Vec<(ChunkId, Vec<u8>)> = missing_list
        .iter()
        .map(|(id, _)| (*id, chunk_data_map[id].clone()))
        .collect();

    let source_symbols = symbolize(&missing_chunks);
    let n = source_symbols.len();
    let sym_refs: Vec<&[u8; SYMBOL_SIZE]> = source_symbols.iter().collect();

    let session_id: u64 = 10;
    let object_id: u64 = 20;
    let update_id: u64 = 30;

    let mut decoder = SsxDecoder::new(n);

    // Feed first half as SYM.
    let sym_count = n / 2;
    for i in 0..sym_count {
        decoder.add_sym(i, source_symbols[i]);
    }

    // Feed MIX symbols until complete.
    for t in 0..2000u32 {
        if decoder.is_complete() {
            break;
        }
        let (indices, _) = mix_indices(session_id, object_id, update_id, t, n as u32);
        let payload = encode_mix(&sym_refs, &indices);
        decoder.add_mix(t, payload, session_id, object_id, update_id);
    }

    assert!(
        decoder.is_complete(),
        "decoder must complete with SYM + MIX. Known: {}/{}",
        decoder.known_count(),
        n
    );

    // Reconstruct and verify.
    let recovered_symbols = decoder.take_symbols();
    let mut reconstructed_chunks: HashMap<ChunkId, Vec<u8>> = HashMap::new();
    let mut sym_off = 0;
    for (chunk_id, chunk_len) in &missing_list {
        let num_syms = if (*chunk_len as usize) == 0 {
            1
        } else {
            (*chunk_len as usize + SYMBOL_SIZE - 1) / SYMBOL_SIZE
        };
        let mut chunk_bytes = Vec::with_capacity(*chunk_len as usize);
        for s in 0..num_syms {
            chunk_bytes.extend_from_slice(recovered_symbols[&(sym_off + s)].as_ref());
        }
        chunk_bytes.truncate(*chunk_len as usize);
        reconstructed_chunks.insert(*chunk_id, chunk_bytes);
        sym_off += num_syms;
    }

    let mut final_data = Vec::new();
    for entry in &target_recipe.entries {
        final_data.extend_from_slice(&reconstructed_chunks[&entry.chunk_id]);
    }
    assert_eq!(final_data, original_data, "byte-for-byte match with MIX recovery");
}

#[test]
fn loopback_missing_wire_encoding() {
    // Verify MissingWire encoding format is correct.
    let data = generate_test_data(100_000, 77);
    let chunks = chunker::chunk(&data);
    let chunk_meta: Vec<(ChunkId, usize)> = chunks.iter().map(|(id, d)| (*id, d.len())).collect();
    let target_recipe = Recipe::from_chunks(&chunk_meta);
    let target_keys: HashSet<ChunkId> = target_recipe.entries.iter().map(|e| e.chunk_id).collect();
    let missing_list = compute_missing_list(&target_recipe, &target_keys);

    let wire = encode_missing_wire(&missing_list);

    // Parse it back.
    assert_eq!(wire[0], 0, "version must be 0");
    let (count, mut off) = varint::decode(&wire, 1).unwrap();
    assert_eq!(count as usize, missing_list.len());

    for (expected_id, expected_len) in &missing_list {
        let mut id = [0u8; 16];
        id.copy_from_slice(&wire[off..off + 16]);
        off += 16;
        assert_eq!(ChunkId(id), *expected_id);

        let (len, new_off) = varint::decode(&wire, off).unwrap();
        off = new_off;
        assert_eq!(len, *expected_len);
    }
    assert_eq!(off, wire.len(), "all bytes consumed");

    // Verify digest is deterministic.
    let d1 = h256(&wire);
    let d2 = h256(&encode_missing_wire(&missing_list));
    assert_eq!(d1, d2);
}

#[test]
fn loopback_recipe_digest_matches() {
    // Verify that sender and receiver compute the same H_target.
    let data = generate_test_data(150_000, 123);
    let chunks = chunker::chunk(&data);
    let chunk_meta: Vec<(ChunkId, usize)> = chunks.iter().map(|(id, d)| (*id, d.len())).collect();
    let target_recipe = Recipe::from_chunks(&chunk_meta);
    let h_target = target_recipe.digest();

    // Simulate receiver: gets ops from empty base, applies, computes digest.
    let base = Recipe { entries: vec![] };
    let ops_data = recipe_ops::diff(&base, &target_recipe);
    let receiver_recipe = recipe_ops::apply(&base, &ops_data).unwrap();
    assert_eq!(receiver_recipe.digest(), h_target, "H_target must match on both sides");
}
