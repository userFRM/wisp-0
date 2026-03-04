use serde::{Deserialize, Serialize};

use wisp_core::chunk_id::h128;
use wisp_core::chunker;
use wisp_core::ict::Ict;
use wisp_core::recipe::Recipe;
use wisp_core::ssx::{encode_mix, mix_indices, symbolize};
use wisp_core::types::{ChunkId, SYMBOL_SIZE};

// ---------------------------------------------------------------------------
// Vector types
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct CdcVector {
    pub input_hex: String,
    pub chunks: Vec<ChunkVector>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct ChunkVector {
    pub offset: usize,
    pub len: usize,
    pub chunk_id_hex: String,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct RecipeVector {
    pub entries: Vec<RecipeEntryVec>,
    pub wire_hex: String,
    pub digest_hex: String,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct RecipeEntryVec {
    pub chunk_id_hex: String,
    pub chunk_len: u64,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct IctVector {
    pub keys_hex: Vec<String>,
    pub m_log2: u8,
    pub peeled_hex: Vec<String>,
    pub success: bool,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct SsxVector {
    pub session_id: u64,
    pub object_id: u64,
    pub update_id: u64,
    pub n: u32,
    pub mixes: Vec<MixVector>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct MixVector {
    pub t: u32,
    pub degree: usize,
    pub indices: Vec<usize>,
    pub payload_hex: String,
}

/// End-to-end Phase 2–4 vector: OFFER → HAVE_ICT → PLAN glue.
#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct E2eVector {
    pub name: String,
    pub base_hex: Option<String>,
    pub target_hex: String,
    pub target_recipe_entries: Vec<RecipeEntryVec>,
    pub target_recipe_digest_hex: String,
    pub have_chunk_ids_hex: Vec<String>,
    pub diff_ict_wire_hex: String,
    pub missing_chunk_ids_hex: Vec<String>,
    pub missing_digest_hex: String,
    pub n_symbols: u32,
}

// ---------------------------------------------------------------------------
// Hex helpers
// ---------------------------------------------------------------------------

fn to_hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

fn from_hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

// ---------------------------------------------------------------------------
// Generate
// ---------------------------------------------------------------------------

pub fn generate_cdc_vectors() -> Vec<CdcVector> {
    let mut vectors = Vec::new();

    // Vector 1: small data (single chunk)
    let input1 = b"Hello, WISP conformance vectors!";
    vectors.push(make_cdc_vector(input1));

    // Vector 2: larger deterministic data (multiple chunks possible)
    let input2: Vec<u8> = (0u32..100_000)
        .map(|i| ((i.wrapping_mul(2654435761)) >> 16) as u8)
        .collect();
    vectors.push(make_cdc_vector(&input2));

    // Vector 3: empty
    vectors.push(make_cdc_vector(b""));

    vectors
}

fn make_cdc_vector(input: &[u8]) -> CdcVector {
    let chunks = chunker::chunk(input);
    let mut offset = 0;
    let chunk_vecs: Vec<ChunkVector> = chunks
        .iter()
        .map(|(id, data)| {
            let cv = ChunkVector {
                offset,
                len: data.len(),
                chunk_id_hex: to_hex(&id.0),
            };
            offset += data.len();
            cv
        })
        .collect();

    CdcVector {
        input_hex: to_hex(input),
        chunks: chunk_vecs,
    }
}

pub fn generate_recipe_vectors() -> Vec<RecipeVector> {
    let mut vectors = Vec::new();

    // Vector 1: empty recipe
    let r1 = Recipe { entries: vec![] };
    vectors.push(make_recipe_vector(&r1));

    // Vector 2: single entry
    let r2 = Recipe::from_chunks(&[(h128(b"chunk-alpha"), 4096)]);
    vectors.push(make_recipe_vector(&r2));

    // Vector 3: multiple entries
    let entries: Vec<(ChunkId, usize)> = (0..5)
        .map(|i| {
            let id = h128(format!("chunk-{i}").as_bytes());
            (id, 1024 * (i + 1))
        })
        .collect();
    let r3 = Recipe::from_chunks(&entries);
    vectors.push(make_recipe_vector(&r3));

    vectors
}

fn make_recipe_vector(recipe: &Recipe) -> RecipeVector {
    let wire = recipe.encode_wire();
    let digest = recipe.digest();

    RecipeVector {
        entries: recipe
            .entries
            .iter()
            .map(|e| RecipeEntryVec {
                chunk_id_hex: to_hex(&e.chunk_id.0),
                chunk_len: e.chunk_len,
            })
            .collect(),
        wire_hex: to_hex(&wire),
        digest_hex: to_hex(&digest.0),
    }
}

pub fn generate_ict_vectors() -> Vec<IctVector> {
    let mut vectors = Vec::new();

    // Vector 1: small set, all peel
    let keys: Vec<ChunkId> = (0u32..5).map(|i| h128(&i.to_le_bytes())).collect();
    let mut ict = Ict::with_estimated_missing(5);
    let m_log2 = ict.m_log2;
    for k in &keys {
        ict.insert(k);
    }
    let mut peeled = ict.peel().unwrap();
    peeled.sort_by_key(|k| k.0);
    let mut sorted_keys = keys.clone();
    sorted_keys.sort_by_key(|k| k.0);

    vectors.push(IctVector {
        keys_hex: sorted_keys.iter().map(|k| to_hex(&k.0)).collect(),
        m_log2,
        peeled_hex: peeled.iter().map(|k| to_hex(&k.0)).collect(),
        success: true,
    });

    // Vector 2: subtract to find missing
    let all_keys: Vec<ChunkId> = (0u32..10).map(|i| h128(&i.to_le_bytes())).collect();
    let bob_keys: Vec<ChunkId> = (0u32..7).map(|i| h128(&i.to_le_bytes())).collect();
    let mut alice = Ict::with_estimated_missing(10);
    let m_log2_2 = alice.m_log2;
    let mut bob = Ict::new(alice.m_log2);
    for k in &all_keys {
        alice.insert(k);
    }
    for k in &bob_keys {
        bob.insert(k);
    }
    let mut diff = alice.subtract(&bob).unwrap();
    let mut missing = diff.peel().unwrap();
    missing.sort_by_key(|k| k.0);

    let mut expected_missing: Vec<ChunkId> = (7u32..10).map(|i| h128(&i.to_le_bytes())).collect();
    expected_missing.sort_by_key(|k| k.0);

    vectors.push(IctVector {
        keys_hex: expected_missing.iter().map(|k| to_hex(&k.0)).collect(),
        m_log2: m_log2_2,
        peeled_hex: missing.iter().map(|k| to_hex(&k.0)).collect(),
        success: true,
    });

    vectors
}

pub fn generate_ssx_vectors() -> Vec<SsxVector> {
    let session_id: u64 = 100;
    let object_id: u64 = 200;
    let update_id: u64 = 300;

    // Create source symbols from known data.
    let id = ChunkId([0; 16]);
    let chunks = vec![
        (id, vec![0xAA; 1024]),
        (id, vec![0xBB; 1024]),
        (id, vec![0xCC; 1024]),
    ];
    let source = symbolize(&chunks);
    let n = source.len() as u32;
    let sym_refs: Vec<&[u8; SYMBOL_SIZE]> = source.iter().collect();

    let mut mixes = Vec::new();
    for t in 0..10u32 {
        let (indices, degree) = mix_indices(session_id, object_id, update_id, t, n);
        let payload = encode_mix(&sym_refs, &indices);
        mixes.push(MixVector {
            t,
            degree,
            indices,
            payload_hex: to_hex(&payload),
        });
    }

    vec![SsxVector {
        session_id,
        object_id,
        update_id,
        n,
        mixes,
    }]
}

pub fn generate_e2e_vectors() -> Vec<E2eVector> {
    let mut vectors = Vec::new();

    // Vector 1: full sync — receiver has nothing
    let target1: Vec<u8> = (0u32..80_000)
        .map(|i| ((i.wrapping_mul(2654435761)) >> 16) as u8)
        .collect();
    vectors.push(make_e2e_vector("full_sync", None, &target1, &[]));

    // Vector 2: incremental sync — receiver has base chunks, target shares prefix
    let base2: Vec<u8> = (0u32..60_000)
        .map(|i| ((i.wrapping_mul(2654435761)) >> 16) as u8)
        .collect();
    let mut target2: Vec<u8> = (0u32..60_000)
        .map(|i| ((i.wrapping_mul(2654435761)) >> 16) as u8)
        .collect();
    target2.extend((0u32..20_000).map(|i| ((i.wrapping_mul(1234567891)) >> 16) as u8));

    let base_chunks = chunker::chunk(&base2);
    let have_ids: Vec<ChunkId> = base_chunks.iter().map(|(id, _)| *id).collect();
    vectors.push(make_e2e_vector(
        "incremental_sync",
        Some(&base2),
        &target2,
        &have_ids,
    ));

    // Vector 3: duplicate ChunkId in target recipe — chunk A appears at positions 0 and 2.
    // Sender dedupes for symbolization; receiver must do the same during reassembly.
    let chunk_a_data = vec![0x41u8; 4096];
    let chunk_b_data = vec![0x42u8; 4096];
    let chunk_a_id = wisp_core::chunk_id::h128(&chunk_a_data);
    let chunk_b_id = wisp_core::chunk_id::h128(&chunk_b_data);

    // Target = [A, B, A] — recipe has chunk_a_id twice
    let target3: Vec<u8> = [&chunk_a_data[..], &chunk_b_data[..], &chunk_a_data[..]].concat();
    let target_recipe3 = Recipe::from_chunks(&[
        (chunk_a_id, 4096),
        (chunk_b_id, 4096),
        (chunk_a_id, 4096),
    ]);
    // Build chunks list matching the recipe (with actual data for symbolization)
    let target_chunks3 = vec![
        (chunk_a_id, chunk_a_data.clone()),
        (chunk_b_id, chunk_b_data.clone()),
        (chunk_a_id, chunk_a_data.clone()),
    ];
    vectors.push(make_e2e_vector_manual(
        "duplicate_chunk_in_recipe",
        &target3,
        &target_recipe3,
        &target_chunks3,
        &[], // receiver has nothing
    ));

    vectors
}

fn make_e2e_vector(
    name: &str,
    base: Option<&[u8]>,
    target: &[u8],
    have_ids: &[ChunkId],
) -> E2eVector {
    let target_chunks = chunker::chunk(target);
    let chunk_meta: Vec<(ChunkId, usize)> = target_chunks
        .iter()
        .map(|(id, d)| (*id, d.len()))
        .collect();
    let target_recipe = Recipe::from_chunks(&chunk_meta);
    let target_digest = target_recipe.digest();

    // Unique target chunk IDs
    let mut target_ids: Vec<ChunkId> = target_recipe.entries.iter().map(|e| e.chunk_id).collect();
    target_ids.sort_by_key(|k| k.0);
    target_ids.dedup();

    // Relevant have set: unique chunk IDs the receiver has that appear in target
    let mut have_set: Vec<ChunkId> = have_ids
        .iter()
        .copied()
        .filter(|id| target_ids.contains(id))
        .collect();
    have_set.sort_by_key(|k| k.0);
    have_set.dedup();

    // Build difference ICT (target - have)
    let d_est = target_ids.len().saturating_sub(have_set.len()).max(1);
    let mut target_ict = Ict::with_estimated_missing(d_est);
    for id in &target_ids {
        target_ict.insert(id);
    }
    let mut have_ict = Ict::new(target_ict.m_log2);
    for id in &have_set {
        have_ict.insert(id);
    }
    let mut diff_ict = target_ict.subtract(&have_ict).unwrap();
    let diff_wire = diff_ict.encode_wire();

    let mut missing = diff_ict.peel().unwrap();
    missing.sort_by_key(|k| k.0);

    // Missing chunks in recipe order, first appearance per ChunkId (deduped).
    let mut seen = Vec::new();
    let missing_entries: Vec<(ChunkId, usize)> = target_recipe
        .entries
        .iter()
        .filter(|e| {
            missing.contains(&e.chunk_id) && !seen.contains(&e.chunk_id) && {
                seen.push(e.chunk_id);
                true
            }
        })
        .map(|e| (e.chunk_id, e.chunk_len as usize))
        .collect();
    let missing_recipe = Recipe::from_chunks(&missing_entries);
    let missing_digest = missing_recipe.digest();

    // Symbolize missing chunks to get n_symbols
    let missing_chunk_data: Vec<(ChunkId, Vec<u8>)> = missing_entries
        .iter()
        .map(|(id, _)| {
            let data = target_chunks
                .iter()
                .find(|(cid, _)| cid == id)
                .unwrap()
                .1
                .clone();
            (*id, data)
        })
        .collect();
    let source_symbols = symbolize(&missing_chunk_data);

    E2eVector {
        name: name.to_string(),
        base_hex: base.map(to_hex),
        target_hex: to_hex(target),
        target_recipe_entries: target_recipe
            .entries
            .iter()
            .map(|e| RecipeEntryVec {
                chunk_id_hex: to_hex(&e.chunk_id.0),
                chunk_len: e.chunk_len,
            })
            .collect(),
        target_recipe_digest_hex: to_hex(&target_digest.0),
        have_chunk_ids_hex: have_set.iter().map(|id| to_hex(&id.0)).collect(),
        diff_ict_wire_hex: to_hex(&diff_wire),
        missing_chunk_ids_hex: missing.iter().map(|id| to_hex(&id.0)).collect(),
        missing_digest_hex: to_hex(&missing_digest.0),
        n_symbols: source_symbols.len() as u32,
    }
}

/// Like make_e2e_vector but takes a pre-built recipe and chunk list (for duplicate-ChunkId tests).
fn make_e2e_vector_manual(
    name: &str,
    target: &[u8],
    target_recipe: &Recipe,
    target_chunks: &[(ChunkId, Vec<u8>)],
    have_ids: &[ChunkId],
) -> E2eVector {
    let target_digest = target_recipe.digest();

    let mut target_ids: Vec<ChunkId> = target_recipe.entries.iter().map(|e| e.chunk_id).collect();
    target_ids.sort_by_key(|k| k.0);
    target_ids.dedup();

    let mut have_set: Vec<ChunkId> = have_ids
        .iter()
        .copied()
        .filter(|id| target_ids.contains(id))
        .collect();
    have_set.sort_by_key(|k| k.0);
    have_set.dedup();

    let d_est = target_ids.len().saturating_sub(have_set.len()).max(1);
    let mut target_ict = Ict::with_estimated_missing(d_est);
    for id in &target_ids {
        target_ict.insert(id);
    }
    let mut have_ict = Ict::new(target_ict.m_log2);
    for id in &have_set {
        have_ict.insert(id);
    }
    let mut diff_ict = target_ict.subtract(&have_ict).unwrap();
    let diff_wire = diff_ict.encode_wire();

    let mut missing = diff_ict.peel().unwrap();
    missing.sort_by_key(|k| k.0);

    // Deduped missing entries (first appearance per ChunkId)
    let mut seen = Vec::new();
    let missing_entries: Vec<(ChunkId, usize)> = target_recipe
        .entries
        .iter()
        .filter(|e| {
            missing.contains(&e.chunk_id) && !seen.contains(&e.chunk_id) && {
                seen.push(e.chunk_id);
                true
            }
        })
        .map(|e| (e.chunk_id, e.chunk_len as usize))
        .collect();
    let missing_recipe = Recipe::from_chunks(&missing_entries);
    let missing_digest = missing_recipe.digest();

    let missing_chunk_data: Vec<(ChunkId, Vec<u8>)> = missing_entries
        .iter()
        .map(|(id, _)| {
            let data = target_chunks
                .iter()
                .find(|(cid, _)| cid == id)
                .unwrap()
                .1
                .clone();
            (*id, data)
        })
        .collect();
    let source_symbols = symbolize(&missing_chunk_data);

    E2eVector {
        name: name.to_string(),
        base_hex: None,
        target_hex: to_hex(target),
        target_recipe_entries: target_recipe
            .entries
            .iter()
            .map(|e| RecipeEntryVec {
                chunk_id_hex: to_hex(&e.chunk_id.0),
                chunk_len: e.chunk_len,
            })
            .collect(),
        target_recipe_digest_hex: to_hex(&target_digest.0),
        have_chunk_ids_hex: have_set.iter().map(|id| to_hex(&id.0)).collect(),
        diff_ict_wire_hex: to_hex(&diff_wire),
        missing_chunk_ids_hex: missing.iter().map(|id| to_hex(&id.0)).collect(),
        missing_digest_hex: to_hex(&missing_digest.0),
        n_symbols: source_symbols.len() as u32,
    }
}

// ---------------------------------------------------------------------------
// Verify
// ---------------------------------------------------------------------------

pub fn verify_cdc_vectors(vectors: &[CdcVector]) -> Result<(), String> {
    for (i, v) in vectors.iter().enumerate() {
        let input = from_hex(&v.input_hex);
        let chunks = chunker::chunk(&input);

        if chunks.len() != v.chunks.len() {
            return Err(format!(
                "CDC vector {}: expected {} chunks, got {}",
                i,
                v.chunks.len(),
                chunks.len()
            ));
        }

        let mut offset = 0;
        for (j, (id, data)) in chunks.iter().enumerate() {
            let expected = &v.chunks[j];
            if offset != expected.offset {
                return Err(format!(
                    "CDC vector {}, chunk {}: offset mismatch ({} vs {})",
                    i, j, offset, expected.offset
                ));
            }
            if data.len() != expected.len {
                return Err(format!(
                    "CDC vector {}, chunk {}: len mismatch ({} vs {})",
                    i,
                    j,
                    data.len(),
                    expected.len
                ));
            }
            let id_hex = to_hex(&id.0);
            if id_hex != expected.chunk_id_hex {
                return Err(format!(
                    "CDC vector {}, chunk {}: chunk_id mismatch",
                    i, j
                ));
            }
            offset += data.len();
        }
    }
    Ok(())
}

pub fn verify_recipe_vectors(vectors: &[RecipeVector]) -> Result<(), String> {
    for (i, v) in vectors.iter().enumerate() {
        let chunks: Vec<(ChunkId, usize)> = v
            .entries
            .iter()
            .map(|e| {
                let mut id = [0u8; 16];
                id.copy_from_slice(&from_hex(&e.chunk_id_hex));
                (ChunkId(id), e.chunk_len as usize)
            })
            .collect();

        let recipe = Recipe::from_chunks(&chunks);
        let wire = recipe.encode_wire();
        let digest = recipe.digest();

        if to_hex(&wire) != v.wire_hex {
            return Err(format!("Recipe vector {}: wire mismatch", i));
        }
        if to_hex(&digest.0) != v.digest_hex {
            return Err(format!("Recipe vector {}: digest mismatch", i));
        }
    }
    Ok(())
}

pub fn verify_ict_vectors(vectors: &[IctVector]) -> Result<(), String> {
    for (i, v) in vectors.iter().enumerate() {
        let keys: Vec<ChunkId> = v
            .keys_hex
            .iter()
            .map(|h| {
                let mut id = [0u8; 16];
                id.copy_from_slice(&from_hex(h));
                ChunkId(id)
            })
            .collect();

        let mut ict = Ict::new(v.m_log2);
        for k in &keys {
            ict.insert(k);
        }

        match ict.peel() {
            Ok(mut peeled) => {
                if !v.success {
                    return Err(format!("ICT vector {}: expected failure, got success", i));
                }
                peeled.sort_by_key(|k| k.0);
                let peeled_hex: Vec<String> = peeled.iter().map(|k| to_hex(&k.0)).collect();
                if peeled_hex != v.peeled_hex {
                    return Err(format!("ICT vector {}: peeled set mismatch", i));
                }
            }
            Err(_) => {
                if v.success {
                    return Err(format!("ICT vector {}: expected success, got failure", i));
                }
            }
        }
    }
    Ok(())
}

pub fn verify_ssx_vectors(vectors: &[SsxVector]) -> Result<(), String> {
    for (i, v) in vectors.iter().enumerate() {
        // Reconstruct source symbols from known data.
        let id = ChunkId([0; 16]);
        let chunks = vec![
            (id, vec![0xAA; 1024]),
            (id, vec![0xBB; 1024]),
            (id, vec![0xCC; 1024]),
        ];
        let source = symbolize(&chunks);
        let sym_refs: Vec<&[u8; SYMBOL_SIZE]> = source.iter().collect();

        for m in &v.mixes {
            let (indices, degree) =
                mix_indices(v.session_id, v.object_id, v.update_id, m.t, v.n);
            if degree != m.degree {
                return Err(format!(
                    "SSX vector {}, t={}: degree mismatch ({} vs {})",
                    i, m.t, degree, m.degree
                ));
            }
            if indices != m.indices {
                return Err(format!(
                    "SSX vector {}, t={}: indices mismatch",
                    i, m.t
                ));
            }
            let payload = encode_mix(&sym_refs, &indices);
            if to_hex(&payload) != m.payload_hex {
                return Err(format!(
                    "SSX vector {}, t={}: payload mismatch",
                    i, m.t
                ));
            }
        }
    }
    Ok(())
}

pub fn verify_e2e_vectors(vectors: &[E2eVector]) -> Result<(), String> {
    for v in vectors.iter() {
        let target = from_hex(&v.target_hex);

        // Reconstruct recipe from vector's entries (handles both CDC and manual recipes).
        let chunk_meta: Vec<(ChunkId, usize)> = v
            .target_recipe_entries
            .iter()
            .map(|e| {
                let mut id = [0u8; 16];
                id.copy_from_slice(&from_hex(&e.chunk_id_hex));
                (ChunkId(id), e.chunk_len as usize)
            })
            .collect();
        let target_recipe = Recipe::from_chunks(&chunk_meta);

        // Split target bytes into chunks according to recipe lengths.
        let mut offset = 0usize;
        let target_chunks: Vec<(ChunkId, Vec<u8>)> = chunk_meta
            .iter()
            .map(|(id, len)| {
                let data = target[offset..offset + len].to_vec();
                offset += len;
                (*id, data)
            })
            .collect();

        // 1. Verify target recipe digest
        let target_digest = target_recipe.digest();
        if to_hex(&target_digest.0) != v.target_recipe_digest_hex {
            return Err(format!("E2E '{}': target recipe digest mismatch", v.name));
        }

        // 2. Parse have_chunk_ids
        let have_set: Vec<ChunkId> = v
            .have_chunk_ids_hex
            .iter()
            .map(|h| {
                let mut id = [0u8; 16];
                id.copy_from_slice(&from_hex(h));
                ChunkId(id)
            })
            .collect();

        // 3. Build difference ICT and verify wire
        let mut target_ids: Vec<ChunkId> =
            target_recipe.entries.iter().map(|e| e.chunk_id).collect();
        target_ids.sort_by_key(|k| k.0);
        target_ids.dedup();

        let d_est = target_ids.len().saturating_sub(have_set.len()).max(1);
        let mut target_ict = Ict::with_estimated_missing(d_est);
        for id in &target_ids {
            target_ict.insert(id);
        }
        let mut have_ict = Ict::new(target_ict.m_log2);
        for id in &have_set {
            have_ict.insert(id);
        }
        let mut diff_ict = target_ict
            .subtract(&have_ict)
            .map_err(|e| format!("E2E '{}': ICT subtract failed: {:?}", v.name, e))?;
        let diff_wire = diff_ict.encode_wire();
        if to_hex(&diff_wire) != v.diff_ict_wire_hex {
            return Err(format!("E2E '{}': diff ICT wire mismatch", v.name));
        }

        // 4. Peel and verify missing set
        let mut missing = diff_ict
            .peel()
            .map_err(|e| format!("E2E '{}': ICT peel failed: {:?}", v.name, e))?;
        missing.sort_by_key(|k| k.0);
        let missing_hex: Vec<String> = missing.iter().map(|k| to_hex(&k.0)).collect();
        if missing_hex != v.missing_chunk_ids_hex {
            return Err(format!("E2E '{}': missing set mismatch", v.name));
        }

        // 5. Verify missing_digest (first appearance per ChunkId, deduped)
        let mut seen = Vec::new();
        let missing_entries: Vec<(ChunkId, usize)> = target_recipe
            .entries
            .iter()
            .filter(|e| {
                missing.contains(&e.chunk_id) && !seen.contains(&e.chunk_id) && {
                    seen.push(e.chunk_id);
                    true
                }
            })
            .map(|e| (e.chunk_id, e.chunk_len as usize))
            .collect();
        let missing_recipe = Recipe::from_chunks(&missing_entries);
        if to_hex(&missing_recipe.digest().0) != v.missing_digest_hex {
            return Err(format!("E2E '{}': missing_digest mismatch", v.name));
        }

        // 6. Verify n_symbols
        let missing_chunk_data: Vec<(ChunkId, Vec<u8>)> = missing_entries
            .iter()
            .map(|(id, _)| {
                let data = target_chunks
                    .iter()
                    .find(|(cid, _)| cid == id)
                    .unwrap()
                    .1
                    .clone();
                (*id, data)
            })
            .collect();
        let source_symbols = symbolize(&missing_chunk_data);
        if source_symbols.len() as u32 != v.n_symbols {
            return Err(format!(
                "E2E '{}': n_symbols mismatch ({} vs {})",
                v.name,
                source_symbols.len(),
                v.n_symbols
            ));
        }
    }
    Ok(())
}
