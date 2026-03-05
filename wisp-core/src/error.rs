#[cfg(not(feature = "std"))]
use core::fmt;

#[cfg(feature = "std")]
use thiserror::Error;

#[derive(Debug)]
#[cfg_attr(feature = "std", derive(Error))]
pub enum WispError {
    #[cfg_attr(feature = "std", error("varint overflow: shift exceeded 63 bits"))]
    VarintOverflow,

    #[cfg_attr(feature = "std", error("unexpected end of buffer"))]
    BufferUnderflow,

    #[cfg_attr(feature = "std", error("invalid frame magic: expected 0x5057, got 0x{0:04x}"))]
    InvalidMagic(u16),

    #[cfg_attr(feature = "std", error("unsupported protocol version: {0}"))]
    UnsupportedVersion(u8),

    #[cfg_attr(feature = "std", error("unknown frame type: 0x{0:02x}"))]
    UnknownFrameType(u8),

    #[cfg_attr(feature = "std", error("reserved field not zero"))]
    ReservedFieldNonZero,

    #[cfg_attr(feature = "std", error("channel mismatch: type 0x{frame_type:02x} on chan {chan}"))]
    ChannelMismatch { frame_type: u8, chan: u8 },

    #[cfg_attr(feature = "std", error("payload too large: {len} bytes (max {max})"))]
    PayloadTooLarge { len: u32, max: u32 },

    #[cfg_attr(feature = "std", error("ICT peel failed: {remaining} non-zero cells remain"))]
    IctPeelFailed { remaining: usize },

    #[cfg_attr(feature = "std", error("ICT table size mismatch: self.m_log2={self_m} != other.m_log2={other_m}"))]
    IctSizeMismatch { self_m: u8, other_m: u8 },

    #[cfg_attr(feature = "std", error("ICT table size exceeds limit: m_log2={m_log2} > max={max}"))]
    IctSizeExceeded { m_log2: u8, max: u8 },

    #[cfg_attr(feature = "std", error("recipe hash mismatch"))]
    RecipeHashMismatch,

    #[cfg_attr(feature = "std", error("chunk hash mismatch for chunk {0:?}"))]
    ChunkHashMismatch(crate::types::ChunkId),

    #[cfg_attr(feature = "std", error("plan mismatch: missing_digest does not match"))]
    PlanMismatch,

    #[cfg_attr(feature = "std", error("base digest mismatch"))]
    BaseDigestMismatch,

    #[cfg_attr(feature = "std", error("invalid recipe version: {0}"))]
    InvalidRecipeVersion(u8),

    #[cfg_attr(feature = "std", error("invalid chunker profile: {0}"))]
    InvalidChunkerProfile(u8),

    #[cfg_attr(feature = "std", error("invalid capsule id: {0}"))]
    InvalidCapsuleId(u32),

    #[cfg_attr(feature = "std", error("duplicate chunk_id with inconsistent chunk_len"))]
    InconsistentChunkLen,

    #[cfg_attr(feature = "std", error("invalid recipe opcode: 0x{0:02x}"))]
    InvalidRecipeOpcode(u8),

    #[cfg_attr(feature = "std", error("HMAC verification failed"))]
    HmacVerificationFailed,

    #[cfg_attr(feature = "std", error("unknown auth mode: 0x{0:02x}"))]
    InvalidAuthMode(u8),

    #[cfg_attr(feature = "std", error("unexpected trailing bytes in payload"))]
    TrailingBytes,

    #[cfg_attr(feature = "std", error("replay detected: frame sequence {seq} already seen or too old"))]
    ReplayDetected { seq: u64 },

    #[cfg_attr(feature = "std", error("session frame limit exceeded: {count} >= {max}"))]
    SessionFrameLimitExceeded { count: u64, max: u64 },

    #[cfg_attr(feature = "std", error("session duration exceeded"))]
    SessionDurationExceeded,

    #[cfg_attr(feature = "std", error("X25519 key exchange failed"))]
    KeyExchangeFailed,

    #[cfg_attr(feature = "std", error("key_id mismatch: no matching PSK in keyring"))]
    KeyIdMismatch,

    #[cfg_attr(feature = "std", error("invalid data"))]
    InvalidData,

    #[cfg(feature = "std")]
    #[cfg_attr(feature = "std", error("IO error: {0}"))]
    Io(#[from] std::io::Error),
}

#[cfg(not(feature = "std"))]
impl fmt::Display for WispError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::VarintOverflow => write!(f, "varint overflow: shift exceeded 63 bits"),
            Self::BufferUnderflow => write!(f, "unexpected end of buffer"),
            Self::InvalidMagic(m) => write!(f, "invalid frame magic: expected 0x5057, got 0x{m:04x}"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported protocol version: {v}"),
            Self::UnknownFrameType(t) => write!(f, "unknown frame type: 0x{t:02x}"),
            Self::ReservedFieldNonZero => write!(f, "reserved field not zero"),
            Self::ChannelMismatch { frame_type, chan } => write!(f, "channel mismatch: type 0x{frame_type:02x} on chan {chan}"),
            Self::PayloadTooLarge { len, max } => write!(f, "payload too large: {len} bytes (max {max})"),
            Self::IctPeelFailed { remaining } => write!(f, "ICT peel failed: {remaining} non-zero cells remain"),
            Self::IctSizeMismatch { self_m, other_m } => write!(f, "ICT table size mismatch: self.m_log2={self_m} != other.m_log2={other_m}"),
            Self::IctSizeExceeded { m_log2, max } => write!(f, "ICT table size exceeds limit: m_log2={m_log2} > max={max}"),
            Self::RecipeHashMismatch => write!(f, "recipe hash mismatch"),
            Self::ChunkHashMismatch(id) => write!(f, "chunk hash mismatch for chunk {id:?}"),
            Self::PlanMismatch => write!(f, "plan mismatch: missing_digest does not match"),
            Self::BaseDigestMismatch => write!(f, "base digest mismatch"),
            Self::InvalidRecipeVersion(v) => write!(f, "invalid recipe version: {v}"),
            Self::InvalidChunkerProfile(p) => write!(f, "invalid chunker profile: {p}"),
            Self::InvalidCapsuleId(id) => write!(f, "invalid capsule id: {id}"),
            Self::InconsistentChunkLen => write!(f, "duplicate chunk_id with inconsistent chunk_len"),
            Self::InvalidRecipeOpcode(op) => write!(f, "invalid recipe opcode: 0x{op:02x}"),
            Self::HmacVerificationFailed => write!(f, "HMAC verification failed"),
            Self::InvalidAuthMode(m) => write!(f, "unknown auth mode: 0x{m:02x}"),
            Self::TrailingBytes => write!(f, "unexpected trailing bytes in payload"),
            Self::ReplayDetected { seq } => write!(f, "replay detected: frame sequence {seq} already seen or too old"),
            Self::SessionFrameLimitExceeded { count, max } => write!(f, "session frame limit exceeded: {count} >= {max}"),
            Self::SessionDurationExceeded => write!(f, "session duration exceeded"),
            Self::KeyExchangeFailed => write!(f, "X25519 key exchange failed"),
            Self::KeyIdMismatch => write!(f, "key_id mismatch: no matching PSK in keyring"),
            Self::InvalidData => write!(f, "invalid data"),
        }
    }
}

pub type Result<T> = core::result::Result<T, WispError>;
