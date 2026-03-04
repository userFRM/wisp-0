use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use hashbrown::HashMap;

use crate::ssx::mix_indices;
use crate::types::SYMBOL_SIZE;

// ---------------------------------------------------------------------------
// Bitmask helpers (Vec<u64> arbitrary-width)
// ---------------------------------------------------------------------------

fn mask_words(n: usize) -> usize {
    n.div_ceil(64)
}

fn new_mask(n: usize) -> Vec<u64> {
    vec![0u64; mask_words(n)]
}

fn set_bit(mask: &mut [u64], bit: usize) {
    mask[bit / 64] |= 1u64 << (bit % 64);
}

fn clear_bit(mask: &mut [u64], bit: usize) {
    mask[bit / 64] &= !(1u64 << (bit % 64));
}

fn test_bit(mask: &[u64], bit: usize) -> bool {
    (mask[bit / 64] >> (bit % 64)) & 1 != 0
}

fn is_zero(mask: &[u64]) -> bool {
    mask.iter().all(|&w| w == 0)
}

/// Returns the index of the lowest set bit, or None if all zero.
fn lowest_set_bit(mask: &[u64]) -> Option<usize> {
    for (i, &w) in mask.iter().enumerate() {
        if w != 0 {
            return Some(i * 64 + w.trailing_zeros() as usize);
        }
    }
    None
}

/// Population count of the entire bitmask.
fn popcount(mask: &[u64]) -> u32 {
    mask.iter().map(|w| w.count_ones()).sum()
}

fn xor_mask(a: &mut [u64], b: &[u64]) {
    for (x, y) in a.iter_mut().zip(b.iter()) {
        *x ^= *y;
    }
}

fn xor_sym(a: &mut [u8; SYMBOL_SIZE], b: &[u8; SYMBOL_SIZE]) {
    for (x, y) in a.iter_mut().zip(b.iter()) {
        *x ^= *y;
    }
}

// ---------------------------------------------------------------------------
// PivotRow
// ---------------------------------------------------------------------------

struct PivotRow {
    mask: Vec<u64>,
    rhs: Box<[u8; SYMBOL_SIZE]>,
}

// ---------------------------------------------------------------------------
// SsxDecoder
// ---------------------------------------------------------------------------

/// Sparse GF(2) Gaussian-elimination fountain decoder.
pub struct SsxDecoder {
    known: HashMap<usize, Box<[u8; SYMBOL_SIZE]>>,
    pivots: HashMap<usize, PivotRow>,
    n: usize,
}

impl SsxDecoder {
    pub fn new(n: usize) -> Self {
        Self {
            known: HashMap::new(),
            pivots: HashMap::new(),
            n,
        }
    }

    /// Feed a known source symbol.
    pub fn add_sym(&mut self, k: usize, data: [u8; SYMBOL_SIZE]) {
        if self.known.contains_key(&k) {
            return;
        }
        self.known.insert(k, Box::new(data));
        self._substitute_known(k);
        self._propagate_singles();
    }

    /// Feed a coded (MIX) symbol for fountain index `t`.
    pub fn add_mix(
        &mut self,
        t: u32,
        payload: [u8; SYMBOL_SIZE],
        session_id: u64,
        object_id: u64,
        update_id: u64,
    ) {
        let (indices, _degree) = mix_indices(session_id, object_id, update_id, t, self.n as u32);

        let mut rhs = Box::new(payload);
        let mut mask = new_mask(self.n);

        for idx in indices {
            if let Some(known_sym) = self.known.get(&idx) {
                xor_sym(&mut rhs, known_sym);
            } else {
                // Toggle bit (handles repeated indices via XOR).
                if test_bit(&mask, idx) {
                    clear_bit(&mut mask, idx);
                } else {
                    set_bit(&mut mask, idx);
                }
            }
        }

        if is_zero(&mask) {
            return; // trivially satisfied
        }

        self._insert_equation(mask, rhs);
        self._propagate_singles();
    }

    pub fn is_complete(&self) -> bool {
        self.known.len() == self.n
    }

    pub fn known_count(&self) -> usize {
        self.known.len()
    }

    pub fn take_symbols(self) -> HashMap<usize, Box<[u8; SYMBOL_SIZE]>> {
        self.known
    }

    // -----------------------------------------------------------------------
    // Internal
    // -----------------------------------------------------------------------

    fn _substitute_known(&mut self, k: usize) {
        let known_sym = self.known[&k].clone();

        // Collect pivot keys that reference bit k.
        let to_process: Vec<usize> = self
            .pivots
            .keys()
            .copied()
            .filter(|&p| {
                if let Some(row) = self.pivots.get(&p) {
                    k < row.mask.len() * 64 && test_bit(&row.mask, k)
                } else {
                    false
                }
            })
            .collect();

        let mut to_reinsert = Vec::new();
        for p in to_process {
            if let Some(mut row) = self.pivots.remove(&p) {
                xor_sym(&mut row.rhs, &known_sym);
                clear_bit(&mut row.mask, k);
                if !is_zero(&row.mask) {
                    to_reinsert.push(row);
                }
            }
        }

        for row in to_reinsert {
            self._insert_equation(row.mask, row.rhs);
        }
    }

    fn _insert_equation(&mut self, mut mask: Vec<u64>, mut rhs: Box<[u8; SYMBOL_SIZE]>) {
        while let Some(p) = lowest_set_bit(&mask) {
            if let Some(pivot) = self.pivots.get(&p) {
                xor_mask(&mut mask, &pivot.mask);
                xor_sym(&mut rhs, &pivot.rhs);
            } else {
                self.pivots.insert(p, PivotRow { mask, rhs });
                return;
            }
        }
        // mask is zero: linearly dependent, discard.
    }

    fn _propagate_singles(&mut self) {
        loop {
            // Find a pivot whose mask has exactly 1 bit set.
            let single = self
                .pivots
                .iter()
                .find(|(_, row)| popcount(&row.mask) == 1)
                .map(|(&p, _)| p);

            let Some(p) = single else { break };

            let row = self.pivots.remove(&p).unwrap();
            let k = lowest_set_bit(&row.mask).unwrap();

            if !self.known.contains_key(&k) {
                self.known.insert(k, row.rhs);
                self._substitute_known(k);
            }
            // If already known (shouldn't happen normally), just discard the row.
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssx::{compute_seed, encode_mix, symbolize};
    use crate::types::ChunkId;

    #[test]
    fn add_sym_recovers_all() {
        let n = 5;
        let mut dec = SsxDecoder::new(n);

        let symbols: Vec<[u8; SYMBOL_SIZE]> = (0..n)
            .map(|i| {
                let mut s = [0u8; SYMBOL_SIZE];
                s[0] = i as u8;
                s[1] = (i * 7) as u8;
                s
            })
            .collect();

        for (i, sym) in symbols.iter().enumerate() {
            dec.add_sym(i, *sym);
        }

        assert!(dec.is_complete());
        let recovered = dec.take_symbols();
        for (i, sym) in symbols.iter().enumerate() {
            assert_eq!(recovered[&i].as_ref(), sym);
        }
    }

    #[test]
    fn decode_with_mix_symbols() {
        let n = 4;
        let session_id: u64 = 100;
        let object_id: u64 = 200;
        let update_id: u64 = 300;

        // Create source symbols.
        let symbols: Vec<[u8; SYMBOL_SIZE]> = (0..n)
            .map(|i| {
                let mut s = [0u8; SYMBOL_SIZE];
                for (j, byte) in s.iter_mut().enumerate() {
                    *byte = ((i * 31 + j * 7) & 0xFF) as u8;
                }
                s
            })
            .collect();

        let sym_refs: Vec<&[u8; SYMBOL_SIZE]> = symbols.iter().collect();

        let mut dec = SsxDecoder::new(n);

        // Feed symbol 0 and 1 directly.
        dec.add_sym(0, symbols[0]);
        dec.add_sym(1, symbols[1]);

        // Now feed MIX symbols until complete.
        for t in 0..200u32 {
            if dec.is_complete() {
                break;
            }
            let (indices, _) = mix_indices(session_id, object_id, update_id, t, n as u32);
            let payload = encode_mix(&sym_refs, &indices);
            dec.add_mix(t, payload, session_id, object_id, update_id);
        }

        assert!(dec.is_complete(), "Decoder should complete. Known: {}/{}", dec.known_count(), n);
        let recovered = dec.take_symbols();
        for (i, sym) in symbols.iter().enumerate() {
            assert_eq!(recovered[&i].as_ref(), sym, "Symbol {} mismatch", i);
        }
    }

    #[test]
    fn full_round_trip() {
        let session_id: u64 = 42;
        let object_id: u64 = 7;
        let update_id: u64 = 1;

        let id = ChunkId([0; 16]);
        // 3 chunks, various sizes.
        let chunks = vec![
            (id, vec![0xAA; 1500]),  // 2 symbols
            (id, vec![0xBB; 1024]),  // 1 symbol
            (id, vec![0xCC; 500]),   // 1 symbol (padded)
        ];

        let source = symbolize(&chunks);
        let n = source.len();
        assert_eq!(n, 4);

        let sym_refs: Vec<&[u8; SYMBOL_SIZE]> = source.iter().collect();

        let mut dec = SsxDecoder::new(n);

        // Send first symbol as SYM.
        dec.add_sym(0, source[0]);

        // Send the rest as MIX.
        for t in 0..200u32 {
            if dec.is_complete() {
                break;
            }
            let (indices, _) = mix_indices(session_id, object_id, update_id, t, n as u32);
            let payload = encode_mix(&sym_refs, &indices);
            dec.add_mix(t, payload, session_id, object_id, update_id);
        }

        assert!(dec.is_complete(), "Full round-trip should complete. Known: {}/{}", dec.known_count(), n);
        let recovered = dec.take_symbols();
        for (i, sym) in source.iter().enumerate() {
            assert_eq!(recovered[&i].as_ref(), sym, "Symbol {} mismatch in round trip", i);
        }
    }

    #[test]
    fn mix_only_recovery() {
        // No SYM symbols at all -- pure fountain recovery.
        let session_id: u64 = 999;
        let object_id: u64 = 888;
        let update_id: u64 = 777;
        let n = 3;

        let symbols: Vec<[u8; SYMBOL_SIZE]> = (0..n)
            .map(|i| {
                let mut s = [0u8; SYMBOL_SIZE];
                for (j, byte) in s.iter_mut().enumerate() {
                    *byte = ((i * 13 + j * 3) & 0xFF) as u8;
                }
                s
            })
            .collect();

        let sym_refs: Vec<&[u8; SYMBOL_SIZE]> = symbols.iter().collect();

        let mut dec = SsxDecoder::new(n);

        for t in 0..500u32 {
            if dec.is_complete() {
                break;
            }
            let (indices, _) = mix_indices(session_id, object_id, update_id, t, n as u32);
            let payload = encode_mix(&sym_refs, &indices);
            dec.add_mix(t, payload, session_id, object_id, update_id);
        }

        assert!(dec.is_complete(), "Mix-only should complete. Known: {}/{}", dec.known_count(), n);
        let recovered = dec.take_symbols();
        for (i, sym) in symbols.iter().enumerate() {
            assert_eq!(recovered[&i].as_ref(), sym, "Symbol {} mismatch in mix-only", i);
        }
    }

    #[test]
    fn prng_determinism_seed() {
        let s1 = compute_seed(1, 2, 3, 0);
        let s2 = compute_seed(1, 2, 3, 0);
        assert_eq!(s1, s2);

        let s3 = compute_seed(1, 2, 3, 1);
        assert_ne!(s1, s3);
    }

    #[test]
    fn degree_thresholds() {
        // Verify degree mapping for specific byte values.
        let cases: Vec<(u8, usize)> = vec![
            (0, 3), (127, 3),
            (128, 5), (191, 5),
            (192, 9), (223, 9),
            (224, 17), (255, 17),
        ];
        for (b, expected) in cases {
            let d = if b < 128 { 3 } else if b < 192 { 5 } else if b < 224 { 9 } else { 17 };
            assert_eq!(d, expected, "byte {} should map to degree {}", b, expected);
        }
    }
}
