use alloc::vec;
use alloc::vec::Vec;
use sha2::{Sha256, Digest};

use crate::error::{Result, WispError};
use crate::types::ChunkId;

/// Number of hash functions (k=3).
const K: u8 = 3;

/// Maximum allowed m_log2 (table size 2^24 = 16M cells).
const MAX_M_LOG2: u8 = 24;

/// A single cell in the ICT table (28 bytes).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IctCell {
    pub count: i32,
    pub key_xor: [u8; 16],
    pub hash_xor: u64,
}

/// ICT/0 Invertible Count Table for set reconciliation.
#[derive(Debug, Clone)]
pub struct Ict {
    pub m_log2: u8,
    pub cells: Vec<IctCell>,
}

/// Compute hash64(key) = u64_le(SHA256(0x49 || key)[..8]).
fn hash64(key: &[u8; 16]) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update([0x49]);
    hasher.update(key);
    let hash = hasher.finalize();
    u64::from_le_bytes(hash[..8].try_into().unwrap())
}

/// Compute hj(key, j, m) = u64_le(SHA256(byte(0xA0+j) || key)[..8]) % m.
fn hj(key: &[u8; 16], j: u8, m: usize) -> usize {
    let mut hasher = Sha256::new();
    hasher.update([0xA0 + j]);
    hasher.update(key);
    let hash = hasher.finalize();
    let val = u64::from_le_bytes(hash[..8].try_into().unwrap());
    (val % m as u64) as usize
}

/// Compute m_log2 from estimated missing count d_est.
fn compute_m_log2(d_est: usize) -> u8 {
    // Integer ceiling of (2.5 * d_est + 32) = (5 * d_est + 64) / 2, rounded up
    let raw = (5 * d_est + 64).div_ceil(2);
    let m = raw.next_power_of_two().max(256);
    m.trailing_zeros() as u8
}

impl Ict {
    /// Create a new ICT with the given m_log2 (table has 2^m_log2 cells).
    pub fn new(m_log2: u8) -> Self {
        let m = 1usize << m_log2;
        Self {
            m_log2,
            cells: vec![IctCell::default(); m],
        }
    }

    /// Create an ICT auto-sized for the estimated number of missing keys.
    pub fn with_estimated_missing(d_est: usize) -> Self {
        Self::new(compute_m_log2(d_est))
    }

    /// Number of cells in the table.
    fn m(&self) -> usize {
        1usize << self.m_log2
    }

    /// Insert a key into the table.
    pub fn insert(&mut self, key: &ChunkId) {
        let m = self.m();
        let h64 = hash64(&key.0);
        for j in 0..K {
            let idx = hj(&key.0, j, m);
            self.cells[idx].count += 1;
            xor_16(&mut self.cells[idx].key_xor, &key.0);
            self.cells[idx].hash_xor ^= h64;
        }
    }

    /// Element-wise subtract: self - other. Errors if table sizes differ.
    pub fn subtract(&self, other: &Ict) -> Result<Ict> {
        if self.m_log2 != other.m_log2 {
            return Err(WispError::IctSizeMismatch {
                self_m: self.m_log2,
                other_m: other.m_log2,
            });
        }
        let m = self.m();
        let mut cells = Vec::with_capacity(m);
        for i in 0..m {
            let mut kx = self.cells[i].key_xor;
            xor_16(&mut kx, &other.cells[i].key_xor);
            cells.push(IctCell {
                count: self.cells[i].count - other.cells[i].count,
                key_xor: kx,
                hash_xor: self.cells[i].hash_xor ^ other.cells[i].hash_xor,
            });
        }
        Ok(Ict {
            m_log2: self.m_log2,
            cells,
        })
    }

    /// Peel the table, returning the set of keys with sign +1 (missing keys).
    pub fn peel(&mut self) -> Result<Vec<ChunkId>> {
        let m = self.m();
        let mut stack: Vec<usize> = Vec::new();

        // Initial scan for pure cells.
        for i in 0..m {
            if is_pure(&self.cells[i]) {
                stack.push(i);
            }
        }

        let mut missing = Vec::new();

        while let Some(i) = stack.pop() {
            if self.cells[i].count == 0 {
                continue;
            }
            if !is_pure(&self.cells[i]) {
                continue;
            }

            let key = self.cells[i].key_xor;
            let sign = self.cells[i].count; // +1 or -1
            if sign == 1 {
                missing.push(ChunkId(key));
            }

            let h64 = hash64(&key);
            for j in 0..K {
                let idx = hj(&key, j, m);
                self.cells[idx].count -= sign;
                xor_16(&mut self.cells[idx].key_xor, &key);
                self.cells[idx].hash_xor ^= h64;
                if is_pure(&self.cells[idx]) {
                    stack.push(idx);
                }
            }
        }

        // Check success: all cells must be zero.
        let remaining = self.cells.iter().filter(|c| c.count != 0).count();
        if remaining > 0 {
            return Err(WispError::IctPeelFailed { remaining });
        }

        Ok(missing)
    }

    /// Encode to HAVE_ICT wire format.
    pub fn encode_wire(&self) -> Vec<u8> {
        let m = self.m();
        let mut buf = Vec::with_capacity(4 + m * 28);
        buf.push(self.m_log2);
        buf.push(0); // rsv0
        buf.extend_from_slice(&0u16.to_le_bytes()); // rsv1
        for cell in &self.cells {
            buf.extend_from_slice(&cell.count.to_le_bytes());
            buf.extend_from_slice(&cell.key_xor);
            buf.extend_from_slice(&cell.hash_xor.to_le_bytes());
        }
        buf
    }

    /// Decode from HAVE_ICT wire format.
    pub fn decode_wire(data: &[u8]) -> Result<Self> {
        if data.len() < 4 {
            return Err(WispError::BufferUnderflow);
        }
        let m_log2 = data[0];
        if m_log2 > MAX_M_LOG2 {
            return Err(WispError::IctSizeExceeded {
                m_log2,
                max: MAX_M_LOG2,
            });
        }
        let m = 1usize << m_log2;
        let expected_len = 4 + m * 28;
        if data.len() < expected_len {
            return Err(WispError::BufferUnderflow);
        }

        let mut cells = Vec::with_capacity(m);
        let mut offset = 4;
        for _ in 0..m {
            let count = i32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
            offset += 4;
            let mut key_xor = [0u8; 16];
            key_xor.copy_from_slice(&data[offset..offset + 16]);
            offset += 16;
            let hash_xor = u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap());
            offset += 8;
            cells.push(IctCell {
                count,
                key_xor,
                hash_xor,
            });
        }

        Ok(Ict { m_log2, cells })
    }

    /// Returns true if all cells are zero.
    pub fn is_empty(&self) -> bool {
        self.cells.iter().all(|c| {
            c.count == 0 && c.key_xor == [0u8; 16] && c.hash_xor == 0
        })
    }
}

/// XOR 16 bytes in-place: dst ^= src.
#[inline]
fn xor_16(dst: &mut [u8; 16], src: &[u8; 16]) {
    for i in 0..16 {
        dst[i] ^= src[i];
    }
}

/// A cell is pure if abs(count)==1 and hash64(key_xor)==hash_xor.
#[inline]
fn is_pure(cell: &IctCell) -> bool {
    (cell.count == 1 || cell.count == -1) && hash64(&cell.key_xor) == cell.hash_xor
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chunk_id::h128;

    fn make_key(i: u32) -> ChunkId {
        h128(&i.to_le_bytes())
    }

    #[test]
    fn empty_table_peels_to_empty() {
        let mut ict = Ict::new(8); // 256 cells
        let result = ict.peel().unwrap();
        assert!(result.is_empty());
        assert!(ict.is_empty());
    }

    #[test]
    fn insert_peel_roundtrip_small() {
        let keys: Vec<ChunkId> = (0..5).map(make_key).collect();
        let mut ict = Ict::with_estimated_missing(5);

        for k in &keys {
            ict.insert(k);
        }

        let mut result = ict.peel().unwrap();
        result.sort_by_key(|k| k.0);
        let mut expected = keys.clone();
        expected.sort_by_key(|k| k.0);
        assert_eq!(result, expected);
    }

    #[test]
    fn subtract_identifies_missing() {
        // Alice has keys 0..10, Bob has keys 0..7.
        // Missing from Bob: keys 7, 8, 9.
        let all_keys: Vec<ChunkId> = (0..10).map(make_key).collect();
        let bob_keys: Vec<ChunkId> = (0..7).map(make_key).collect();

        let mut alice = Ict::with_estimated_missing(10);
        let mut bob = Ict::with_estimated_missing(10);

        for k in &all_keys {
            alice.insert(k);
        }
        for k in &bob_keys {
            bob.insert(k);
        }

        let mut diff = alice.subtract(&bob).unwrap();
        let mut missing = diff.peel().unwrap();
        missing.sort_by_key(|k| k.0);

        let mut expected: Vec<ChunkId> = (7..10).map(make_key).collect();
        expected.sort_by_key(|k| k.0);
        assert_eq!(missing, expected);
    }

    #[test]
    fn table_sizing_formula() {
        // d_est=0: ceil(2.5*0+32)=32, next_pow2=32, max(32,256)=256, log2=8
        assert_eq!(compute_m_log2(0), 8);

        // d_est=100: ceil(2.5*100+32)=282, next_pow2=512, max(512,256)=512, log2=9
        assert_eq!(compute_m_log2(100), 9);

        // d_est=1000: ceil(2.5*1000+32)=2532, next_pow2=4096, log2=12
        assert_eq!(compute_m_log2(1000), 12);
    }

    #[test]
    fn wire_roundtrip() {
        let keys: Vec<ChunkId> = (0..8).map(make_key).collect();
        let mut ict = Ict::with_estimated_missing(8);
        for k in &keys {
            ict.insert(k);
        }

        let wire = ict.encode_wire();
        assert_eq!(wire[0], ict.m_log2);
        assert_eq!(wire[1], 0);
        assert_eq!(wire[2], 0);
        assert_eq!(wire[3], 0);

        let decoded = Ict::decode_wire(&wire).unwrap();
        assert_eq!(decoded.m_log2, ict.m_log2);
        assert_eq!(decoded.cells.len(), ict.cells.len());
        for (a, b) in decoded.cells.iter().zip(ict.cells.iter()) {
            assert_eq!(a, b);
        }
    }

    #[test]
    fn subtract_size_mismatch_error() {
        let a = Ict::new(8);
        let b = Ict::new(9);
        assert!(a.subtract(&b).is_err());
    }

    #[test]
    fn large_set_cascade() {
        // 200 keys to exercise the peel cascade.
        let keys: Vec<ChunkId> = (0..200).map(make_key).collect();
        let mut ict = Ict::with_estimated_missing(200);
        for k in &keys {
            ict.insert(k);
        }

        let mut result = ict.peel().unwrap();
        result.sort_by_key(|k| k.0);
        let mut expected = keys.clone();
        expected.sort_by_key(|k| k.0);
        assert_eq!(result, expected);
    }

    #[test]
    fn decode_wire_too_short() {
        assert!(Ict::decode_wire(&[]).is_err());
        assert!(Ict::decode_wire(&[8, 0, 0, 0]).is_err()); // header ok but no cells
    }

    #[test]
    fn is_empty_after_insert() {
        let key = make_key(42);
        let mut ict = Ict::new(8);
        assert!(ict.is_empty());
        ict.insert(&key);
        assert!(!ict.is_empty());
    }
}
