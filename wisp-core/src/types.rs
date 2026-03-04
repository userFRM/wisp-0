use serde::{Deserialize, Serialize};
use core::fmt;

/// 16-byte chunk identifier: first 16 bytes of SHA-256.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ChunkId(pub [u8; 16]);

impl fmt::Debug for ChunkId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ChunkId(")?;
        for b in &self.0[..4] {
            write!(f, "{b:02x}")?;
        }
        write!(f, "...)")
    }
}

/// 32-byte SHA-256 digest.
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Digest32(pub [u8; 32]);

impl fmt::Debug for Digest32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Digest32(")?;
        for b in &self.0[..4] {
            write!(f, "{b:02x}")?;
        }
        write!(f, "...)")
    }
}

/// 8-byte session identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(pub u64);

/// 8-byte object identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ObjectId(pub u64);

/// 8-byte update identifier (starts at 1, increments by 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UpdateId(pub u64);

/// A single entry in a recipe: (chunk_id, chunk_len).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecipeEntry {
    pub chunk_id: ChunkId,
    pub chunk_len: u64,
}

/// Symbol size for SSX/0 fountain coding.
pub const SYMBOL_SIZE: usize = 1024;

/// D0 datagram payload size: 4 (index) + 1024 (data).
pub const D0_PAYLOAD_SIZE: usize = 1028;

/// D0 datagram total size: 80 (header) + 1028 (payload).
pub const D0_FRAME_SIZE: usize = 1108;

/// Frame header size.
pub const HEADER_SIZE: usize = 80;

/// Frame magic number (little-endian: wire bytes 0x57 0x50).
pub const FRAME_MAGIC: u16 = 0x5057;

/// Protocol version.
pub const PROTOCOL_VERSION: u8 = 0;

/// HMAC-SHA256-128 tag size in bytes.
pub const HMAC_TAG_SIZE: usize = 16;

/// D0 datagram total size with HMAC authentication: 1108 + 16 = 1124.
pub const D0_FRAME_SIZE_AUTH: usize = D0_FRAME_SIZE + HMAC_TAG_SIZE;

/// Header flags: bit 0 signals HMAC-SHA256-128 authentication tag present.
pub const FLAGS_AUTH_HMAC: u16 = 0x0001;

/// Maximum frames per session before mandatory restart.
pub const MAX_SESSION_FRAMES: u64 = 1 << 32;

/// Maximum session duration in seconds (default: 1 hour).
pub const MAX_SESSION_DURATION_SECS: u64 = 3600;

/// Auth trailer size for mode 0x02 (X25519-PSK-HKDF): 1 + 32 + 32 + 8 = 73 bytes.
pub const AUTH_TRAILER_V2_SIZE: usize = 73;

/// Hard maximum payload size for C0 (TCP) control frames: 1 MiB.
/// Prevents unbounded allocation from a malicious payload_len header field.
pub const MAX_C0_PAYLOAD: u32 = 1 << 20;
