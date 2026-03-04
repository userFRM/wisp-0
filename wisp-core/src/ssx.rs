use alloc::vec::Vec;
use sha2::{Sha256, Digest};

use crate::types::{ChunkId, SYMBOL_SIZE};

// ---------------------------------------------------------------------------
// PRNG: SHA-256 hash chain
// ---------------------------------------------------------------------------

/// Deterministic PRNG based on a SHA-256 hash chain.
///
/// `stream_0 = seed`, `stream_{i+1} = SHA256(stream_i)`.
/// Bytes are consumed sequentially from the concatenated 32-byte blocks.
pub struct SsxPrng {
    block: [u8; 32],
    pos: usize,
}

impl SsxPrng {
    pub fn new(seed: [u8; 32]) -> Self {
        Self { block: seed, pos: 0 }
    }

    pub fn next_byte(&mut self) -> u8 {
        if self.pos >= 32 {
            let mut h = Sha256::new();
            h.update(self.block);
            self.block = h.finalize().into();
            self.pos = 0;
        }
        let b = self.block[self.pos];
        self.pos += 1;
        b
    }

    pub fn next_u32_le(&mut self) -> u32 {
        let b0 = self.next_byte() as u32;
        let b1 = self.next_byte() as u32;
        let b2 = self.next_byte() as u32;
        let b3 = self.next_byte() as u32;
        b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
    }
}

// ---------------------------------------------------------------------------
// Seed derivation
// ---------------------------------------------------------------------------

/// Compute the per-symbol seed:
/// `SHA256("SSX0" || session_id[8 LE] || object_id[8 LE] || update_id[8 LE] || t[4 LE])`
pub fn compute_seed(session_id: u64, object_id: u64, update_id: u64, t: u32) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x53, 0x53, 0x58, 0x30]); // "SSX0"
    h.update(session_id.to_le_bytes());
    h.update(object_id.to_le_bytes());
    h.update(update_id.to_le_bytes());
    h.update(t.to_le_bytes());
    h.finalize().into()
}

// ---------------------------------------------------------------------------
// Index / degree mixing
// ---------------------------------------------------------------------------

/// Derive degree and source-symbol indices for fountain symbol `t`.
///
/// Returns `(indices, degree)`.
pub fn mix_indices(
    session_id: u64,
    object_id: u64,
    update_id: u64,
    t: u32,
    n: u32,
) -> (Vec<usize>, usize) {
    let seed = compute_seed(session_id, object_id, update_id, t);
    let mut prng = SsxPrng::new(seed);

    // Degree from first PRNG byte.
    let b = prng.next_byte();
    let degree: usize = if b < 128 {
        3
    } else if b < 192 {
        5
    } else if b < 224 {
        9
    } else {
        17
    };

    // Index selection.
    let mut indices = Vec::with_capacity(degree);
    for _ in 0..degree {
        let r = prng.next_u32_le();
        indices.push((r % n) as usize);
    }

    (indices, degree)
}

// ---------------------------------------------------------------------------
// Payload encoding
// ---------------------------------------------------------------------------

/// XOR selected source symbols into a single repair symbol.
pub fn encode_mix(source_symbols: &[&[u8; SYMBOL_SIZE]], indices: &[usize]) -> [u8; SYMBOL_SIZE] {
    let mut out = [0u8; SYMBOL_SIZE];
    for &idx in indices {
        let sym = source_symbols[idx];
        for (o, &s) in out.iter_mut().zip(sym.iter()) {
            *o ^= s;
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Symbolize: chunks -> source symbols
// ---------------------------------------------------------------------------

/// Convert a list of (ChunkId, data) pairs into 1024-byte source symbols.
/// The last symbol of each chunk is zero-padded if shorter than 1024 bytes.
pub fn symbolize(chunks: &[(ChunkId, Vec<u8>)]) -> Vec<[u8; SYMBOL_SIZE]> {
    let mut symbols = Vec::new();
    for (_id, data) in chunks {
        let mut offset = 0;
        while offset < data.len() {
            let mut sym = [0u8; SYMBOL_SIZE];
            let end = (offset + SYMBOL_SIZE).min(data.len());
            sym[..end - offset].copy_from_slice(&data[offset..end]);
            symbols.push(sym);
            offset += SYMBOL_SIZE;
        }
        // If data is empty, produce one zero symbol.
        if data.is_empty() {
            symbols.push([0u8; SYMBOL_SIZE]);
        }
    }
    symbols
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(not(feature = "std"))]
    use alloc::vec;

    #[test]
    fn prng_determinism() {
        let seed = compute_seed(1, 2, 3, 42);
        let mut p1 = SsxPrng::new(seed);
        let mut p2 = SsxPrng::new(seed);
        for _ in 0..200 {
            assert_eq!(p1.next_byte(), p2.next_byte());
        }
    }

    #[test]
    fn degree_distribution() {
        // b < 128 -> 3
        // b < 192 -> 5
        // b < 224 -> 9
        // b >= 224 -> 17
        let seed = [0u8; 32]; // first byte is 0 -> degree 3
        let mut prng = SsxPrng::new(seed);
        let b = prng.next_byte();
        assert!(b < 128);

        let seed_high = [0xFF; 32]; // first byte is 255 -> degree 17
        let mut prng2 = SsxPrng::new(seed_high);
        let b2 = prng2.next_byte();
        assert!(b2 >= 224);
    }

    #[test]
    fn mix_indices_basic() {
        let (indices, degree) = mix_indices(1, 2, 3, 0, 100);
        assert!(degree == 3 || degree == 5 || degree == 9 || degree == 17);
        assert_eq!(indices.len(), degree);
        for &idx in &indices {
            assert!(idx < 100);
        }
    }

    #[test]
    fn encode_mix_xor() {
        let a = [0xAA; SYMBOL_SIZE];
        let b = [0x55; SYMBOL_SIZE];
        let c = [0xFF; SYMBOL_SIZE];

        let symbols: Vec<&[u8; SYMBOL_SIZE]> = vec![&a, &b, &c];
        let result = encode_mix(&symbols, &[0, 1]);
        assert_eq!(result, [0xFF; SYMBOL_SIZE]);

        let result2 = encode_mix(&symbols, &[0, 1, 2]);
        assert_eq!(result2, [0x00; SYMBOL_SIZE]); // AA ^ 55 ^ FF = 00
    }

    #[test]
    fn symbolize_padding() {
        let id = ChunkId([0; 16]);
        // 1025 bytes -> 2 symbols (second is 1 byte + 1023 zeros)
        let data = vec![0xBB; 1025];
        let syms = symbolize(&[(id, data)]);
        assert_eq!(syms.len(), 2);
        assert_eq!(syms[0], [0xBB; SYMBOL_SIZE]);
        assert_eq!(syms[1][0], 0xBB);
        assert_eq!(syms[1][1], 0x00);
    }

    #[test]
    fn symbolize_exact() {
        let id = ChunkId([0; 16]);
        let data = vec![0xCC; SYMBOL_SIZE];
        let syms = symbolize(&[(id, data)]);
        assert_eq!(syms.len(), 1);
        assert_eq!(syms[0], [0xCC; SYMBOL_SIZE]);
    }

    #[test]
    fn symbolize_empty() {
        let id = ChunkId([0; 16]);
        let syms = symbolize(&[(id, vec![])]);
        assert_eq!(syms.len(), 1);
        assert_eq!(syms[0], [0u8; SYMBOL_SIZE]);
    }
}
