use alloc::vec::Vec;

use crate::chunk_id::h256;
use crate::error::{Result, WispError};
use crate::types::{ChunkId, Digest32, RecipeEntry};
use crate::varint;

const RECIPE_VERSION: u8 = 0;
const CHUNKER_PROFILE: u8 = 0;

/// An ordered list of recipe entries describing how an object is chunked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recipe {
    pub entries: Vec<RecipeEntry>,
}

impl Recipe {
    /// Build a Recipe from a slice of (ChunkId, chunk_len) pairs.
    pub fn from_chunks(chunks: &[(ChunkId, usize)]) -> Self {
        Self {
            entries: chunks
                .iter()
                .map(|&(chunk_id, len)| RecipeEntry {
                    chunk_id,
                    chunk_len: len as u64,
                })
                .collect(),
        }
    }

    /// Encode to RecipeWire binary format.
    ///
    /// Layout:
    ///   u8   recipe_version (0)
    ///   u8   chunker_profile (0)
    ///   varint num_chunks
    ///   repeat num_chunks:
    ///     bytes16 chunk_id
    ///     varint  chunk_len
    pub fn encode_wire(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(RECIPE_VERSION);
        buf.push(CHUNKER_PROFILE);
        varint::encode_vec(self.entries.len() as u64, &mut buf);
        for entry in &self.entries {
            buf.extend_from_slice(&entry.chunk_id.0);
            varint::encode_vec(entry.chunk_len, &mut buf);
        }
        buf
    }

    /// Decode from RecipeWire binary format.
    ///
    /// Validates that recipe_version == 0 and chunker_profile == 0.
    pub fn decode_wire(data: &[u8]) -> Result<Self> {
        if data.len() < 2 {
            return Err(WispError::BufferUnderflow);
        }

        let version = data[0];
        if version != RECIPE_VERSION {
            return Err(WispError::InvalidRecipeVersion(version));
        }

        let profile = data[1];
        if profile != CHUNKER_PROFILE {
            return Err(WispError::InvalidChunkerProfile(profile));
        }

        let mut off = 2;
        let (num_chunks, new_off) = varint::decode(data, off)?;
        off = new_off;

        let mut entries = Vec::with_capacity(num_chunks as usize);
        for _ in 0..num_chunks {
            if off + 16 > data.len() {
                return Err(WispError::BufferUnderflow);
            }
            let mut id = [0u8; 16];
            id.copy_from_slice(&data[off..off + 16]);
            off += 16;

            let (chunk_len, new_off) = varint::decode(data, off)?;
            off = new_off;

            entries.push(RecipeEntry {
                chunk_id: ChunkId(id),
                chunk_len,
            });
        }

        Ok(Self { entries })
    }

    /// Compute H_recipe = SHA-256(RecipeWire(self)).
    pub fn digest(&self) -> Digest32 {
        h256(&self.encode_wire())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chunk_id::h128;
    #[cfg(not(feature = "std"))]
    use alloc::{format, vec};

    #[test]
    fn round_trip_empty() {
        let recipe = Recipe { entries: vec![] };
        let wire = recipe.encode_wire();
        let decoded = Recipe::decode_wire(&wire).unwrap();
        assert_eq!(recipe, decoded);
    }

    #[test]
    fn round_trip_single() {
        let id = h128(b"chunk-0");
        let recipe = Recipe::from_chunks(&[(id, 4096)]);
        let wire = recipe.encode_wire();
        let decoded = Recipe::decode_wire(&wire).unwrap();
        assert_eq!(recipe, decoded);
    }

    #[test]
    fn round_trip_multiple() {
        let chunks: Vec<(ChunkId, usize)> = (0..10)
            .map(|i| {
                let id = h128(format!("chunk-{i}").as_bytes());
                (id, 1024 * (i + 1))
            })
            .collect();
        let recipe = Recipe::from_chunks(&chunks);
        let wire = recipe.encode_wire();
        let decoded = Recipe::decode_wire(&wire).unwrap();
        assert_eq!(recipe, decoded);
    }

    #[test]
    fn digest_deterministic() {
        let id = h128(b"hello");
        let recipe = Recipe::from_chunks(&[(id, 100)]);
        let d1 = recipe.digest();
        let d2 = recipe.digest();
        assert_eq!(d1, d2);
    }

    #[test]
    fn digest_changes_with_content() {
        let r1 = Recipe::from_chunks(&[(h128(b"a"), 10)]);
        let r2 = Recipe::from_chunks(&[(h128(b"b"), 10)]);
        assert_ne!(r1.digest(), r2.digest());
    }

    #[test]
    fn invalid_version() {
        let mut wire = Recipe { entries: vec![] }.encode_wire();
        wire[0] = 1; // bad version
        let err = Recipe::decode_wire(&wire).unwrap_err();
        assert!(matches!(err, WispError::InvalidRecipeVersion(1)));
    }

    #[test]
    fn invalid_profile() {
        let mut wire = Recipe { entries: vec![] }.encode_wire();
        wire[1] = 3; // bad profile
        let err = Recipe::decode_wire(&wire).unwrap_err();
        assert!(matches!(err, WispError::InvalidChunkerProfile(3)));
    }

    #[test]
    fn truncated_data_errors() {
        let recipe = Recipe::from_chunks(&[(h128(b"x"), 999)]);
        let wire = recipe.encode_wire();
        // Cut off mid-entry
        let truncated = &wire[..wire.len() - 5];
        assert!(Recipe::decode_wire(truncated).is_err());
    }

    #[test]
    fn wire_format_layout() {
        let recipe = Recipe { entries: vec![] };
        let wire = recipe.encode_wire();
        assert_eq!(wire[0], 0); // version
        assert_eq!(wire[1], 0); // profile
        assert_eq!(wire[2], 0); // num_chunks = 0
        assert_eq!(wire.len(), 3);
    }

    #[test]
    fn empty_buffer_errors() {
        assert!(Recipe::decode_wire(&[]).is_err());
        assert!(Recipe::decode_wire(&[0]).is_err());
    }
}
