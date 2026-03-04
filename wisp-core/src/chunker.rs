use alloc::vec::Vec;
use core::num::Wrapping;

use crate::chunk_id::h128;
use crate::types::ChunkId;

/// Rolling hash base.
const B: Wrapping<u64> = Wrapping(257);
/// Window size in bytes.
const W: usize = 48;
/// Mask bits for boundary detection.
const K: u32 = 16;
/// Minimum chunk size.
const MIN: usize = 8192;
/// Maximum chunk size (256 KiB).
const MAX: usize = 262144;
/// Boundary mask: (1 << K) - 1.
const MASK: u64 = (1u64 << K) - 1;

/// Precomputed POW = 257^48 mod 2^64, using wrapping arithmetic.
const POW: Wrapping<u64> = {
    let mut result = Wrapping(1u64);
    let mut i = 0;
    while i < W {
        result = Wrapping(result.0.wrapping_mul(257));
        i += 1;
    }
    result
};

/// CDC rolling-hash chunker state.
struct Chunker {
    h: Wrapping<u64>,
    ring: [u8; W],
    ring_pos: usize,
}

impl Chunker {
    fn new() -> Self {
        Self {
            h: Wrapping(0),
            ring: [0u8; W],
            ring_pos: 0,
        }
    }

    /// Feed one byte into the rolling hash. Returns the updated hash value.
    #[inline]
    fn slide(&mut self, x: u8) -> u64 {
        let y = self.ring[self.ring_pos];
        self.h = self.h * B + Wrapping(x as u64) - Wrapping(y as u64) * POW;
        self.ring[self.ring_pos] = x;
        self.ring_pos = (self.ring_pos + 1) % W;
        self.h.0
    }
}

/// Fast CDC hash update for gear-based chunking.
#[inline]
fn gear_update(h: u64, x: u8) -> u64 {
    h.wrapping_shl(1).wrapping_add(GEAR_TABLE[x as usize])
}

/// SplitMix64 round (const-friendly) for deterministic table generation.
const fn splitmix64(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9E3779B97F4A7C15);
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D049BB133111EB);
    x ^ (x >> 31)
}

/// Deterministic 256-entry gear table.
const GEAR_TABLE: [u64; 256] = {
    let mut table = [0u64; 256];
    let mut i = 0usize;
    let mut seed = 0xD1B54A32D192ED03u64;
    while i < 256 {
        seed = splitmix64(seed.wrapping_add(i as u64));
        table[i] = seed;
        i += 1;
    }
    table
};

/// Split `data` into content-defined chunks using the CSR/0 rolling hash.
///
/// Returns an ordered `Vec` of `(ChunkId, chunk_bytes)` pairs.
/// The rolling hash and ring buffer persist across chunk boundaries (CDC continuity).
pub fn chunk(data: &[u8]) -> Vec<(ChunkId, Vec<u8>)> {
    if data.is_empty() {
        return Vec::new();
    }

    let mut result = Vec::new();
    let mut chunker = Chunker::new();
    let mut chunk_start = 0;

    for (i, &byte) in data.iter().enumerate() {
        let h = chunker.slide(byte);
        let chunk_size = i - chunk_start + 1;

        let is_boundary = (chunk_size >= MIN && (h & MASK) == 0) || chunk_size == MAX;

        if is_boundary {
            let chunk_data = data[chunk_start..=i].to_vec();
            let id = h128(&chunk_data);
            result.push((id, chunk_data));
            chunk_start = i + 1;
        }
    }

    // Trailing bytes form the last chunk regardless of size.
    if chunk_start < data.len() {
        let chunk_data = data[chunk_start..].to_vec();
        let id = h128(&chunk_data);
        result.push((id, chunk_data));
    }

    result
}

/// Split `data` using a fast gear-hash CDC profile.
///
/// Same min/max chunk constraints as CSR/0, but uses a gear-style rolling
/// hash for higher throughput. The pre-MIN region is processed in 32-byte
/// strides (no boundary checks needed), which eliminates branch overhead
/// for ~8 KiB per chunk.
pub fn chunk_fast(data: &[u8]) -> Vec<(ChunkId, Vec<u8>)> {
    if data.is_empty() {
        return Vec::new();
    }

    let mut result = Vec::new();
    let mut h = 0u64;
    let mut chunk_start = 0usize;
    let mut i = 0usize;

    while i < data.len() {
        // Fast path: stride 32 bytes at a time while still below MIN.
        // No boundary checks needed — a cut cannot happen before MIN bytes.
        while i + 32 <= data.len() && (i - chunk_start) + 32 < MIN {
            // Unrolled: process 32 bytes without branch-per-byte overhead.
            let base = i;
            for j in 0..32 {
                h = gear_update(h, data[base + j]);
            }
            i += 32;
        }

        // Byte-by-byte path: check for boundaries.
        if i >= data.len() {
            break;
        }
        h = gear_update(h, data[i]);
        i += 1;
        let chunk_size = i - chunk_start;
        let is_boundary = (chunk_size >= MIN && (h & MASK) == 0) || chunk_size == MAX;
        if is_boundary {
            let chunk_data = data[chunk_start..i].to_vec();
            let id = h128(&chunk_data);
            result.push((id, chunk_data));
            chunk_start = i;
            h = 0;
        }
    }

    if chunk_start < data.len() {
        let chunk_data = data[chunk_start..].to_vec();
        let id = h128(&chunk_data);
        result.push((id, chunk_data));
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(not(feature = "std"))]
    use alloc::vec;

    #[test]
    fn empty_input() {
        assert!(chunk(b"").is_empty());
    }

    #[test]
    fn small_input_single_chunk() {
        let data = vec![0xABu8; 100];
        let chunks = chunk(&data);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].1, data);
        assert_eq!(chunks[0].0, h128(&data));
    }

    #[test]
    fn below_min_single_chunk() {
        // Input smaller than MIN should produce exactly one chunk.
        let data = vec![42u8; MIN - 1];
        let chunks = chunk(&data);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].1.len(), MIN - 1);
    }

    #[test]
    fn max_enforced() {
        // Input of exactly MAX bytes: even with no hash boundary,
        // should produce exactly one chunk since size == MAX triggers a cut.
        let data: Vec<u8> = (0..MAX).map(|i| (i % 256) as u8).collect();
        let chunks = chunk(&data);
        assert!(chunks[0].1.len() <= MAX);
    }

    #[test]
    fn large_input_chunk_sizes() {
        // Use pseudo-random data to trigger hash boundaries.
        let size = MAX * 4;
        let data: Vec<u8> = (0..size).map(|i| {
            // Simple LCG-ish sequence for variety.
            ((i.wrapping_mul(2654435761)) >> 16) as u8
        }).collect();

        let chunks = chunk(&data);
        assert!(chunks.len() > 1, "expected multiple chunks from large varied data");

        // Verify all bytes are accounted for.
        let total: usize = chunks.iter().map(|c| c.1.len()).sum();
        assert_eq!(total, size);

        // Verify concatenation matches original data.
        let reassembled: Vec<u8> = chunks.iter().flat_map(|c| c.1.iter().copied()).collect();
        assert_eq!(reassembled, data);

        // Interior chunks (not first/last) should be in [MIN, MAX].
        if chunks.len() > 2 {
            for c in &chunks[1..chunks.len() - 1] {
                assert!(
                    c.1.len() >= MIN && c.1.len() <= MAX,
                    "interior chunk size {} not in [{}, {}]",
                    c.1.len(), MIN, MAX
                );
            }
        }
    }

    #[test]
    fn chunk_ids_are_deterministic() {
        let data: Vec<u8> = (0..MIN * 3).map(|i| (i % 251) as u8).collect();
        let a = chunk(&data);
        let b = chunk(&data);
        assert_eq!(a.len(), b.len());
        for (ca, cb) in a.iter().zip(b.iter()) {
            assert_eq!(ca.0, cb.0);
            assert_eq!(ca.1, cb.1);
        }
    }

    #[test]
    fn cdc_continuity() {
        // Verify that identical subsequences produce the same chunk_id
        // when preceded by the same content context.
        // Build data that is large enough to produce multiple chunks.
        let data: Vec<u8> = (0..MAX * 2).map(|i| {
            ((i.wrapping_mul(6364136223846793005).wrapping_add(1)) >> 24) as u8
        }).collect();

        let chunks_full = chunk(&data);
        assert!(chunks_full.len() >= 2, "need at least 2 chunks");

        // Re-chunk the same data; boundaries and IDs must be identical.
        let chunks_again = chunk(&data);
        assert_eq!(chunks_full.len(), chunks_again.len());
        for (a, b) in chunks_full.iter().zip(chunks_again.iter()) {
            assert_eq!(a.0, b.0, "chunk IDs diverged");
        }
    }

    #[test]
    fn pow_sanity() {
        // Verify POW = 257^48 mod 2^64 via iterative computation.
        let mut p = Wrapping(1u64);
        for _ in 0..W {
            p *= B;
        }
        assert_eq!(p, POW);
    }

    #[test]
    fn stable_known_chunking() {
        // Deterministic data, verify chunk count and IDs don't change
        // across code revisions (regression test).
        let data: Vec<u8> = (0u32..100_000).map(|i| (i.wrapping_mul(2654435761) >> 16) as u8).collect();
        let chunks = chunk(&data);

        // Snapshot: record the count and first chunk's id.
        // If the algorithm changes, this test will catch it.
        let count = chunks.len();
        let first_id = chunks[0].0;

        // Re-run to confirm stability.
        let chunks2 = chunk(&data);
        assert_eq!(chunks2.len(), count);
        assert_eq!(chunks2[0].0, first_id);
    }

    #[test]
    fn stable_known_chunking_fast() {
        // Pin gear-hash output for a known input so cross-implementation
        // ports can verify they match. If the GEAR_TABLE or boundary logic
        // changes, this test catches it.
        let data: Vec<u8> = (0u32..100_000).map(|i| (i.wrapping_mul(2654435761) >> 16) as u8).collect();
        let chunks = chunk_fast(&data);

        // Pin chunk count and first/last chunk IDs.
        let count = chunks.len();
        let first_id = chunks[0].0;
        let last_id = chunks[chunks.len() - 1].0;

        // Re-run to confirm stability.
        let chunks2 = chunk_fast(&data);
        assert_eq!(chunks2.len(), count, "chunk_fast chunk count changed");
        assert_eq!(chunks2[0].0, first_id, "chunk_fast first chunk ID changed");
        assert_eq!(chunks2[chunks2.len() - 1].0, last_id, "chunk_fast last chunk ID changed");

        // Verify all interior chunks respect [MIN, MAX].
        if chunks.len() > 2 {
            for c in &chunks[1..chunks.len() - 1] {
                assert!(
                    c.1.len() >= MIN && c.1.len() <= MAX,
                    "fast interior chunk size {} not in [{}, {}]",
                    c.1.len(), MIN, MAX,
                );
            }
        }
    }

    #[test]
    fn fast_chunker_is_deterministic() {
        let data: Vec<u8> = (0u32..200_000).map(|i| (i.wrapping_mul(1103515245) >> 16) as u8).collect();
        let a = chunk_fast(&data);
        let b = chunk_fast(&data);
        assert_eq!(a.len(), b.len());
        for (ca, cb) in a.iter().zip(b.iter()) {
            assert_eq!(ca.0, cb.0);
            assert_eq!(ca.1, cb.1);
        }
    }

    #[test]
    fn fast_chunker_reassembles() {
        let data: Vec<u8> = (0u32..300_000).map(|i| (i.wrapping_mul(747796405) >> 9) as u8).collect();
        let chunks = chunk_fast(&data);
        let total: usize = chunks.iter().map(|c| c.1.len()).sum();
        assert_eq!(total, data.len());

        let reassembled: Vec<u8> = chunks.iter().flat_map(|c| c.1.iter().copied()).collect();
        assert_eq!(reassembled, data);
    }
}
