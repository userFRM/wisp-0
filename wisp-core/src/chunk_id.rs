use sha2::{Digest, Sha256};

use crate::types::{ChunkId, Digest32};

/// Compute H128(data) = first 16 bytes of SHA-256(data).
pub fn h128(data: &[u8]) -> ChunkId {
    let hash = Sha256::digest(data);
    let mut id = [0u8; 16];
    id.copy_from_slice(&hash[..16]);
    ChunkId(id)
}

/// Compute H256(data) = SHA-256(data).
pub fn h256(data: &[u8]) -> Digest32 {
    let hash = Sha256::digest(data);
    Digest32(hash.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn h128_deterministic() {
        let a = h128(b"hello world");
        let b = h128(b"hello world");
        assert_eq!(a, b);
    }

    #[test]
    fn h128_different_inputs() {
        let a = h128(b"hello");
        let b = h128(b"world");
        assert_ne!(a, b);
    }

    #[test]
    fn h256_known() {
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let d = h256(b"");
        assert_eq!(d.0[0], 0xe3);
        assert_eq!(d.0[1], 0xb0);
    }

    #[test]
    fn h128_is_prefix_of_h256() {
        let data = b"test data";
        let id = h128(data);
        let digest = h256(data);
        assert_eq!(&id.0[..], &digest.0[..16]);
    }
}
