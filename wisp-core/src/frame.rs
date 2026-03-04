use alloc::vec;
use alloc::vec::Vec;

use crate::error::{Result, WispError};
use crate::types::{Digest32, FLAGS_AUTH_HMAC, FRAME_MAGIC, HEADER_SIZE, PROTOCOL_VERSION};
use crate::varint;

// ---------------------------------------------------------------------------
// Frame type codes
// ---------------------------------------------------------------------------

// Control (chan = 0)
const HELLO: u8 = 0x01;
const SELECT: u8 = 0x02;
const OFFER: u8 = 0x03;
const HAVE_ICT: u8 = 0x04;
const ICT_FAIL: u8 = 0x05;
const PLAN: u8 = 0x06;
const NEEDMORE: u8 = 0x07;
const COMMIT: u8 = 0x08;
const ACK: u8 = 0x09;
const FORK: u8 = 0x0A;

// Data (chan = 1)
const SYM: u8 = 0x20;
const MIX: u8 = 0x21;

// ---------------------------------------------------------------------------
// FrameHeader
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameHeader {
    pub frame_type: u8,
    pub flags: u16,
    pub payload_len: u32,
    pub session_id: u64,
    pub object_id: u64,
    pub update_id: u64,
    pub frame_id: u64,
    pub capsule_id: u32,
    pub chan: u8,
    pub base_digest: Digest32,
}

impl FrameHeader {
    /// Encode the header into an 80-byte array (little-endian).
    pub fn encode(&self) -> [u8; HEADER_SIZE] {
        let mut buf = [0u8; HEADER_SIZE];
        // offset 0: magic
        buf[0..2].copy_from_slice(&FRAME_MAGIC.to_le_bytes());
        // offset 2: version
        buf[2] = PROTOCOL_VERSION;
        // offset 3: type
        buf[3] = self.frame_type;
        // offset 4: flags
        buf[4..6].copy_from_slice(&self.flags.to_le_bytes());
        // offset 6: payload_len
        buf[6..10].copy_from_slice(&self.payload_len.to_le_bytes());
        // offset 10: session_id
        buf[10..18].copy_from_slice(&self.session_id.to_le_bytes());
        // offset 18: object_id
        buf[18..26].copy_from_slice(&self.object_id.to_le_bytes());
        // offset 26: update_id
        buf[26..34].copy_from_slice(&self.update_id.to_le_bytes());
        // offset 34: frame_id
        buf[34..42].copy_from_slice(&self.frame_id.to_le_bytes());
        // offset 42: capsule_id
        buf[42..46].copy_from_slice(&self.capsule_id.to_le_bytes());
        // offset 46: chan
        buf[46] = self.chan;
        // offset 47: rsv0
        buf[47] = 0;
        // offset 48: base_digest
        buf[48..80].copy_from_slice(&self.base_digest.0);
        buf
    }

    /// Decode an 80-byte header. Validates magic, version, and reserved fields.
    pub fn decode(buf: &[u8; HEADER_SIZE]) -> Result<Self> {
        let magic = u16::from_le_bytes([buf[0], buf[1]]);
        if magic != FRAME_MAGIC {
            return Err(WispError::InvalidMagic(magic));
        }
        let version = buf[2];
        if version != PROTOCOL_VERSION {
            return Err(WispError::UnsupportedVersion(version));
        }
        let flags = u16::from_le_bytes([buf[4], buf[5]]);
        let known_flags = FLAGS_AUTH_HMAC;
        if flags & !known_flags != 0 {
            return Err(WispError::ReservedFieldNonZero);
        }
        let rsv0 = buf[47];
        if rsv0 != 0 {
            return Err(WispError::ReservedFieldNonZero);
        }

        let mut digest = [0u8; 32];
        digest.copy_from_slice(&buf[48..80]);

        Ok(FrameHeader {
            frame_type: buf[3],
            flags,
            payload_len: u32::from_le_bytes([buf[6], buf[7], buf[8], buf[9]]),
            session_id: u64::from_le_bytes(buf[10..18].try_into().unwrap()),
            object_id: u64::from_le_bytes(buf[18..26].try_into().unwrap()),
            update_id: u64::from_le_bytes(buf[26..34].try_into().unwrap()),
            frame_id: u64::from_le_bytes(buf[34..42].try_into().unwrap()),
            capsule_id: u32::from_le_bytes([buf[42], buf[43], buf[44], buf[45]]),
            chan: buf[46],
            base_digest: Digest32(digest),
        })
    }
}

// ---------------------------------------------------------------------------
// Frame
// ---------------------------------------------------------------------------

/// Authentication parameters in HELLO payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HelloAuth {
    /// Mode 0x01 (legacy): PSK-HMAC with 32-byte nonce.
    PskHmac { nonce: [u8; 32] },
    /// Mode 0x02: X25519-PSK-HKDF with nonce, ephemeral public key, and key_id.
    X25519Psk {
        nonce: [u8; 32],
        ephemeral_pub: [u8; 32],
        key_id: [u8; 8],
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    Hello {
        max_control_payload: u32,
        max_data_payload: u32,
        max_m_log2: u8,
        max_symbols: u32,
        profiles: Vec<(u32, u16)>,
        /// Optional authentication parameters.
        auth: Option<HelloAuth>,
    },
    Select {
        capsule_id: u32,
        capsule_ver: u16,
    },
    Offer {
        h_target: Digest32,
        ops: Vec<u8>,
    },
    HaveIct {
        ict_data: Vec<u8>,
    },
    IctFail {
        reason: u8,
    },
    Plan {
        l: u16,
        ssx_profile: u8,
        n: u32,
        missing_digest: Digest32,
    },
    Needmore {
        next_t: u32,
    },
    Commit {
        h_target: Digest32,
    },
    Ack {
        ack_frame_id: u64,
    },
    Fork {
        reason: u8,
        expected: Digest32,
        observed: Digest32,
    },
    Sym {
        k: u32,
        data: Vec<u8>,
    },
    Mix {
        t: u32,
        payload: Vec<u8>,
    },
}

impl Frame {
    /// Return the frame type code for this variant.
    pub fn frame_type_code(&self) -> u8 {
        match self {
            Frame::Hello { .. } => HELLO,
            Frame::Select { .. } => SELECT,
            Frame::Offer { .. } => OFFER,
            Frame::HaveIct { .. } => HAVE_ICT,
            Frame::IctFail { .. } => ICT_FAIL,
            Frame::Plan { .. } => PLAN,
            Frame::Needmore { .. } => NEEDMORE,
            Frame::Commit { .. } => COMMIT,
            Frame::Ack { .. } => ACK,
            Frame::Fork { .. } => FORK,
            Frame::Sym { .. } => SYM,
            Frame::Mix { .. } => MIX,
        }
    }

    /// Return the channel: 0 for control frames, 1 for data frames.
    pub fn channel(&self) -> u8 {
        match self {
            Frame::Sym { .. } | Frame::Mix { .. } => 1,
            _ => 0,
        }
    }

    /// Session-scoped frames have object_id=0, update_id=0, base_digest=zeros.
    pub fn is_session_scoped(&self) -> bool {
        matches!(self, Frame::Hello { .. } | Frame::Select { .. })
    }

    /// Encode the full frame: header bytes followed by payload bytes.
    pub fn encode(&self, header: &FrameHeader) -> Vec<u8> {
        let payload = self.encode_payload();
        let hdr_bytes = header.encode();
        let mut out = Vec::with_capacity(HEADER_SIZE + payload.len());
        out.extend_from_slice(&hdr_bytes);
        out.extend_from_slice(&payload);
        out
    }

    /// Encode just the payload bytes.
    pub fn encode_payload(&self) -> Vec<u8> {
        match self {
            Frame::Hello {
                max_control_payload,
                max_data_payload,
                max_m_log2,
                max_symbols,
                profiles,
                auth,
            } => {
                let mut out = Vec::new();
                out.extend_from_slice(&max_control_payload.to_le_bytes());
                out.extend_from_slice(&max_data_payload.to_le_bytes());
                out.push(*max_m_log2);
                out.extend_from_slice(&max_symbols.to_le_bytes());
                out.push(profiles.len() as u8);
                for &(cid, cver) in profiles {
                    out.extend_from_slice(&cid.to_le_bytes());
                    out.extend_from_slice(&cver.to_le_bytes());
                    out.extend_from_slice(&0u16.to_le_bytes()); // rsv
                }
                match auth {
                    Some(HelloAuth::PskHmac { nonce }) => {
                        out.push(crate::auth::AUTH_MODE_HMAC_SHA256);
                        out.extend_from_slice(nonce);
                    }
                    Some(HelloAuth::X25519Psk { nonce, ephemeral_pub, key_id }) => {
                        out.push(crate::auth::AUTH_MODE_X25519_PSK);
                        out.extend_from_slice(nonce);
                        out.extend_from_slice(ephemeral_pub);
                        out.extend_from_slice(key_id);
                    }
                    None => {}
                }
                out
            }
            Frame::Select {
                capsule_id,
                capsule_ver,
            } => {
                let mut out = Vec::with_capacity(8);
                out.extend_from_slice(&capsule_id.to_le_bytes());
                out.extend_from_slice(&capsule_ver.to_le_bytes());
                out.extend_from_slice(&0u16.to_le_bytes()); // rsv
                out
            }
            Frame::Offer { h_target, ops } => {
                let mut out = Vec::new();
                out.extend_from_slice(&h_target.0);
                varint::encode_vec(ops.len() as u64, &mut out);
                out.extend_from_slice(ops);
                out
            }
            Frame::HaveIct { ict_data } => ict_data.clone(),
            Frame::IctFail { reason } => {
                vec![*reason, 0, 0, 0] // reason, rsv0, rsv1(LE u16)
            }
            Frame::Plan {
                l,
                ssx_profile,
                n,
                missing_digest,
            } => {
                let mut out = Vec::with_capacity(40);
                out.extend_from_slice(&l.to_le_bytes());
                out.push(*ssx_profile);
                out.push(0); // rsv0
                out.extend_from_slice(&n.to_le_bytes());
                out.extend_from_slice(&missing_digest.0);
                out
            }
            Frame::Needmore { next_t } => next_t.to_le_bytes().to_vec(),
            Frame::Commit { h_target } => h_target.0.to_vec(),
            Frame::Ack { ack_frame_id } => ack_frame_id.to_le_bytes().to_vec(),
            Frame::Fork {
                reason,
                expected,
                observed,
            } => {
                let mut out = Vec::with_capacity(68);
                out.push(*reason);
                out.push(0);    // rsv0
                out.extend_from_slice(&0u16.to_le_bytes()); // rsv1
                out.extend_from_slice(&expected.0);
                out.extend_from_slice(&observed.0);
                out
            }
            Frame::Sym { k, data } => {
                let mut out = Vec::with_capacity(4 + data.len());
                out.extend_from_slice(&k.to_le_bytes());
                out.extend_from_slice(data);
                out
            }
            Frame::Mix { t, payload } => {
                let mut out = Vec::with_capacity(4 + payload.len());
                out.extend_from_slice(&t.to_le_bytes());
                out.extend_from_slice(payload);
                out
            }
        }
    }

    /// Decode payload bytes into a Frame variant given the frame type code.
    pub fn decode_payload(frame_type: u8, payload: &[u8]) -> Result<Self> {
        match frame_type {
            HELLO => {
                if payload.len() < 14 {
                    return Err(WispError::BufferUnderflow);
                }
                let max_control_payload = u32::from_le_bytes(payload[0..4].try_into().unwrap());
                let max_data_payload = u32::from_le_bytes(payload[4..8].try_into().unwrap());
                let max_m_log2 = payload[8];
                let max_symbols = u32::from_le_bytes(payload[9..13].try_into().unwrap());
                let profiles_count = payload[13] as usize;
                let expected = 14 + profiles_count * 8;
                if payload.len() < expected {
                    return Err(WispError::BufferUnderflow);
                }
                let mut profiles = Vec::with_capacity(profiles_count);
                let mut off = 14;
                for _ in 0..profiles_count {
                    let cid = u32::from_le_bytes(payload[off..off + 4].try_into().unwrap());
                    let cver = u16::from_le_bytes(payload[off + 4..off + 6].try_into().unwrap());
                    // skip rsv u16 at off+6..off+8
                    profiles.push((cid, cver));
                    off += 8;
                }
                // Optional auth trailer.
                let auth = if payload.len() > off {
                    let mode = payload[off];
                    match mode {
                        crate::auth::AUTH_MODE_HMAC_SHA256 => {
                            // Mode 0x01: 1 + 32 = 33 bytes
                            if payload.len() < off + 33 {
                                return Err(WispError::BufferUnderflow);
                            }
                            if payload.len() > off + 33 {
                                return Err(WispError::TrailingBytes);
                            }
                            let mut nonce = [0u8; 32];
                            nonce.copy_from_slice(&payload[off + 1..off + 33]);
                            Some(HelloAuth::PskHmac { nonce })
                        }
                        crate::auth::AUTH_MODE_X25519_PSK => {
                            // Mode 0x02: 1 + 32 + 32 + 8 = 73 bytes
                            if payload.len() < off + 73 {
                                return Err(WispError::BufferUnderflow);
                            }
                            if payload.len() > off + 73 {
                                return Err(WispError::TrailingBytes);
                            }
                            let mut nonce = [0u8; 32];
                            nonce.copy_from_slice(&payload[off + 1..off + 33]);
                            let mut eph_pub = [0u8; 32];
                            eph_pub.copy_from_slice(&payload[off + 33..off + 65]);
                            let mut key_id = [0u8; 8];
                            key_id.copy_from_slice(&payload[off + 65..off + 73]);
                            Some(HelloAuth::X25519Psk {
                                nonce,
                                ephemeral_pub: eph_pub,
                                key_id,
                            })
                        }
                        _ => return Err(WispError::InvalidAuthMode(mode)),
                    }
                } else {
                    None
                };
                Ok(Frame::Hello {
                    max_control_payload,
                    max_data_payload,
                    max_m_log2,
                    max_symbols,
                    profiles,
                    auth,
                })
            }
            SELECT => {
                if payload.len() < 8 {
                    return Err(WispError::BufferUnderflow);
                }
                let capsule_id = u32::from_le_bytes(payload[0..4].try_into().unwrap());
                let capsule_ver = u16::from_le_bytes(payload[4..6].try_into().unwrap());
                Ok(Frame::Select {
                    capsule_id,
                    capsule_ver,
                })
            }
            OFFER => {
                if payload.len() < 32 {
                    return Err(WispError::BufferUnderflow);
                }
                let mut h_target = [0u8; 32];
                h_target.copy_from_slice(&payload[0..32]);
                let (ops_len, off) = varint::decode(payload, 32)?;
                let ops_len = ops_len as usize;
                if payload.len() < off + ops_len {
                    return Err(WispError::BufferUnderflow);
                }
                let ops = payload[off..off + ops_len].to_vec();
                Ok(Frame::Offer {
                    h_target: Digest32(h_target),
                    ops,
                })
            }
            HAVE_ICT => Ok(Frame::HaveIct {
                ict_data: payload.to_vec(),
            }),
            ICT_FAIL => {
                if payload.len() < 4 {
                    return Err(WispError::BufferUnderflow);
                }
                Ok(Frame::IctFail {
                    reason: payload[0],
                })
            }
            PLAN => {
                if payload.len() < 40 {
                    return Err(WispError::BufferUnderflow);
                }
                let l = u16::from_le_bytes(payload[0..2].try_into().unwrap());
                let ssx_profile = payload[2];
                // payload[3] is rsv0
                let n = u32::from_le_bytes(payload[4..8].try_into().unwrap());
                let mut missing_digest = [0u8; 32];
                missing_digest.copy_from_slice(&payload[8..40]);
                Ok(Frame::Plan {
                    l,
                    ssx_profile,
                    n,
                    missing_digest: Digest32(missing_digest),
                })
            }
            NEEDMORE => {
                if payload.len() < 4 {
                    return Err(WispError::BufferUnderflow);
                }
                let next_t = u32::from_le_bytes(payload[0..4].try_into().unwrap());
                Ok(Frame::Needmore { next_t })
            }
            COMMIT => {
                if payload.len() < 32 {
                    return Err(WispError::BufferUnderflow);
                }
                let mut h_target = [0u8; 32];
                h_target.copy_from_slice(&payload[0..32]);
                Ok(Frame::Commit {
                    h_target: Digest32(h_target),
                })
            }
            ACK => {
                if payload.len() < 8 {
                    return Err(WispError::BufferUnderflow);
                }
                let ack_frame_id = u64::from_le_bytes(payload[0..8].try_into().unwrap());
                Ok(Frame::Ack { ack_frame_id })
            }
            FORK => {
                if payload.len() < 68 {
                    return Err(WispError::BufferUnderflow);
                }
                let reason = payload[0];
                let mut expected = [0u8; 32];
                expected.copy_from_slice(&payload[4..36]);
                let mut observed = [0u8; 32];
                observed.copy_from_slice(&payload[36..68]);
                Ok(Frame::Fork {
                    reason,
                    expected: Digest32(expected),
                    observed: Digest32(observed),
                })
            }
            SYM => {
                if payload.len() < 4 {
                    return Err(WispError::BufferUnderflow);
                }
                let k = u32::from_le_bytes(payload[0..4].try_into().unwrap());
                let data = payload[4..].to_vec();
                Ok(Frame::Sym { k, data })
            }
            MIX => {
                if payload.len() < 4 {
                    return Err(WispError::BufferUnderflow);
                }
                let t = u32::from_le_bytes(payload[0..4].try_into().unwrap());
                let p = payload[4..].to_vec();
                Ok(Frame::Mix { t, payload: p })
            }
            _ => Err(WispError::UnknownFrameType(frame_type)),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_digest(fill: u8) -> Digest32 {
        Digest32([fill; 32])
    }

    fn default_header(frame: &Frame, payload_len: u32) -> FrameHeader {
        FrameHeader {
            frame_type: frame.frame_type_code(),
            flags: 0,
            payload_len,
            session_id: 0x1234_5678_9ABC_DEF0,
            object_id: if frame.is_session_scoped() { 0 } else { 42 },
            update_id: if frame.is_session_scoped() { 0 } else { 7 },
            frame_id: if frame.channel() == 0 { 1 } else { 0 },
            capsule_id: 0,
            chan: frame.channel(),
            base_digest: if frame.is_session_scoped() {
                Digest32::default()
            } else {
                make_digest(0xAB)
            },
        }
    }

    // -- Header round-trip --

    #[test]
    fn header_round_trip() {
        let hdr = FrameHeader {
            frame_type: HELLO,
            flags: 0,
            payload_len: 256,
            session_id: 0xDEAD_BEEF_CAFE_BABE,
            object_id: 0,
            update_id: 0,
            frame_id: 1,
            capsule_id: 0,
            chan: 0,
            base_digest: Digest32::default(),
        };
        let buf = hdr.encode();
        assert_eq!(buf.len(), HEADER_SIZE);
        let decoded = FrameHeader::decode(&buf).unwrap();
        assert_eq!(hdr, decoded);
    }

    #[test]
    fn header_invalid_magic() {
        let mut buf = [0u8; HEADER_SIZE];
        buf[0] = 0xFF;
        buf[1] = 0xFF;
        let err = FrameHeader::decode(&buf).unwrap_err();
        assert!(matches!(err, WispError::InvalidMagic(0xFFFF)));
    }

    #[test]
    fn header_invalid_version() {
        let hdr = FrameHeader {
            frame_type: HELLO,
            flags: 0,
            payload_len: 0,
            session_id: 0,
            object_id: 0,
            update_id: 0,
            frame_id: 0,
            capsule_id: 0,
            chan: 0,
            base_digest: Digest32::default(),
        };
        let mut buf = hdr.encode();
        buf[2] = 99; // bad version
        let err = FrameHeader::decode(&buf).unwrap_err();
        assert!(matches!(err, WispError::UnsupportedVersion(99)));
    }

    #[test]
    fn header_auth_flag_accepted() {
        let hdr = FrameHeader {
            frame_type: HELLO,
            flags: FLAGS_AUTH_HMAC,
            payload_len: 0,
            session_id: 0,
            object_id: 0,
            update_id: 0,
            frame_id: 0,
            capsule_id: 0,
            chan: 0,
            base_digest: Digest32::default(),
        };
        let buf = hdr.encode();
        let decoded = FrameHeader::decode(&buf).unwrap();
        assert_eq!(decoded.flags, FLAGS_AUTH_HMAC);
    }

    #[test]
    fn header_unknown_flags_rejected() {
        let hdr = FrameHeader {
            frame_type: HELLO,
            flags: 0,
            payload_len: 0,
            session_id: 0,
            object_id: 0,
            update_id: 0,
            frame_id: 0,
            capsule_id: 0,
            chan: 0,
            base_digest: Digest32::default(),
        };
        let mut buf = hdr.encode();
        buf[4] = 0x02; // unknown flag bit 1
        let err = FrameHeader::decode(&buf).unwrap_err();
        assert!(matches!(err, WispError::ReservedFieldNonZero));
    }

    #[test]
    fn header_reserved_rsv0_nonzero() {
        let hdr = FrameHeader {
            frame_type: HELLO,
            flags: 0,
            payload_len: 0,
            session_id: 0,
            object_id: 0,
            update_id: 0,
            frame_id: 0,
            capsule_id: 0,
            chan: 0,
            base_digest: Digest32::default(),
        };
        let mut buf = hdr.encode();
        buf[47] = 1; // rsv0 != 0
        let err = FrameHeader::decode(&buf).unwrap_err();
        assert!(matches!(err, WispError::ReservedFieldNonZero));
    }

    // -- Payload round-trips --

    fn payload_round_trip(frame: Frame) {
        let code = frame.frame_type_code();
        let payload = frame.encode_payload();
        let decoded = Frame::decode_payload(code, &payload).unwrap();
        assert_eq!(frame, decoded);
    }

    #[test]
    fn hello_round_trip() {
        payload_round_trip(Frame::Hello {
            max_control_payload: 65536,
            max_data_payload: 1048576,
            max_m_log2: 20,
            max_symbols: 1000,
            profiles: vec![(1, 0), (2, 1)],
            auth: None,
        });
    }

    #[test]
    fn hello_no_profiles() {
        payload_round_trip(Frame::Hello {
            max_control_payload: 4096,
            max_data_payload: 4096,
            max_m_log2: 16,
            max_symbols: 100,
            profiles: vec![],
            auth: None,
        });
    }

    #[test]
    fn hello_with_psk_hmac_round_trip() {
        payload_round_trip(Frame::Hello {
            max_control_payload: 65536,
            max_data_payload: 1028,
            max_m_log2: 20,
            max_symbols: 65536,
            profiles: vec![(1, 0)],
            auth: Some(HelloAuth::PskHmac { nonce: [0xAA; 32] }),
        });
    }

    #[test]
    fn hello_with_x25519_psk_round_trip() {
        payload_round_trip(Frame::Hello {
            max_control_payload: 65536,
            max_data_payload: 1028,
            max_m_log2: 20,
            max_symbols: 65536,
            profiles: vec![(1, 0)],
            auth: Some(HelloAuth::X25519Psk {
                nonce: [0xBB; 32],
                ephemeral_pub: [0xCC; 32],
                key_id: [0xDD; 8],
            }),
        });
    }

    #[test]
    fn select_round_trip() {
        payload_round_trip(Frame::Select {
            capsule_id: 42,
            capsule_ver: 3,
        });
    }

    #[test]
    fn offer_round_trip() {
        payload_round_trip(Frame::Offer {
            h_target: make_digest(0x11),
            ops: vec![1, 2, 3, 4, 5],
        });
    }

    #[test]
    fn offer_empty_ops() {
        payload_round_trip(Frame::Offer {
            h_target: make_digest(0x22),
            ops: vec![],
        });
    }

    #[test]
    fn have_ict_round_trip() {
        payload_round_trip(Frame::HaveIct {
            ict_data: vec![0xAA; 64],
        });
    }

    #[test]
    fn ict_fail_round_trip() {
        payload_round_trip(Frame::IctFail { reason: 3 });
    }

    #[test]
    fn plan_round_trip() {
        payload_round_trip(Frame::Plan {
            l: 1024,
            ssx_profile: 0,
            n: 500,
            missing_digest: make_digest(0x33),
        });
    }

    #[test]
    fn needmore_round_trip() {
        payload_round_trip(Frame::Needmore { next_t: 42 });
    }

    #[test]
    fn commit_round_trip() {
        payload_round_trip(Frame::Commit {
            h_target: make_digest(0x44),
        });
    }

    #[test]
    fn ack_round_trip() {
        payload_round_trip(Frame::Ack {
            ack_frame_id: 0xDEAD_BEEF,
        });
    }

    #[test]
    fn fork_round_trip() {
        payload_round_trip(Frame::Fork {
            reason: 1,
            expected: make_digest(0x55),
            observed: make_digest(0x66),
        });
    }

    #[test]
    fn sym_round_trip() {
        payload_round_trip(Frame::Sym {
            k: 7,
            data: vec![0xBB; 1024],
        });
    }

    #[test]
    fn mix_round_trip() {
        payload_round_trip(Frame::Mix {
            t: 99,
            payload: vec![0xCC; 1024],
        });
    }

    // -- Full frame encode/decode --

    #[test]
    fn full_frame_round_trip() {
        let frame = Frame::Ack {
            ack_frame_id: 12345,
        };
        let payload = frame.encode_payload();
        let hdr = default_header(&frame, payload.len() as u32);
        let wire = frame.encode(&hdr);
        assert_eq!(wire.len(), HEADER_SIZE + payload.len());

        let hdr_buf: [u8; HEADER_SIZE] = wire[..HEADER_SIZE].try_into().unwrap();
        let decoded_hdr = FrameHeader::decode(&hdr_buf).unwrap();
        assert_eq!(hdr, decoded_hdr);

        let decoded_frame =
            Frame::decode_payload(decoded_hdr.frame_type, &wire[HEADER_SIZE..]).unwrap();
        assert_eq!(frame, decoded_frame);
    }

    // -- Channel validation --

    #[test]
    fn control_frames_on_channel_0() {
        let control_frames: Vec<Frame> = vec![
            Frame::Hello {
                max_control_payload: 1024,
                max_data_payload: 1024,
                max_m_log2: 16,
                max_symbols: 100,
                profiles: vec![],
                auth: None,
            },
            Frame::Select {
                capsule_id: 1,
                capsule_ver: 0,
            },
            Frame::Offer {
                h_target: make_digest(0),
                ops: vec![],
            },
            Frame::HaveIct {
                ict_data: vec![],
            },
            Frame::IctFail { reason: 0 },
            Frame::Plan {
                l: 1024,
                ssx_profile: 0,
                n: 0,
                missing_digest: Digest32::default(),
            },
            Frame::Needmore { next_t: 0 },
            Frame::Commit {
                h_target: Digest32::default(),
            },
            Frame::Ack { ack_frame_id: 0 },
            Frame::Fork {
                reason: 0,
                expected: Digest32::default(),
                observed: Digest32::default(),
            },
        ];
        for f in &control_frames {
            assert_eq!(f.channel(), 0, "expected chan=0 for {:?}", f);
        }
    }

    #[test]
    fn data_frames_on_channel_1() {
        let data_frames: Vec<Frame> = vec![
            Frame::Sym {
                k: 0,
                data: vec![0; 1024],
            },
            Frame::Mix {
                t: 0,
                payload: vec![0; 1024],
            },
        ];
        for f in &data_frames {
            assert_eq!(f.channel(), 1, "expected chan=1 for {:?}", f);
        }
    }

    // -- Session-scoped validation --

    #[test]
    fn session_scoped_frames() {
        assert!(Frame::Hello {
            max_control_payload: 0,
            max_data_payload: 0,
            max_m_log2: 0,
            max_symbols: 0,
            profiles: vec![],
            auth: None,
        }
        .is_session_scoped());
        assert!(Frame::Select {
            capsule_id: 0,
            capsule_ver: 0,
        }
        .is_session_scoped());
    }

    #[test]
    fn non_session_scoped_frames() {
        assert!(!Frame::Ack { ack_frame_id: 0 }.is_session_scoped());
        assert!(!Frame::Commit {
            h_target: Digest32::default(),
        }
        .is_session_scoped());
        assert!(!Frame::Sym {
            k: 0,
            data: vec![],
        }
        .is_session_scoped());
    }

    // -- Unknown frame type --

    #[test]
    fn unknown_frame_type() {
        let err = Frame::decode_payload(0xFF, &[]).unwrap_err();
        assert!(matches!(err, WispError::UnknownFrameType(0xFF)));
    }

    // -- Truncated payload detection --

    #[test]
    fn truncated_hello_payload() {
        let err = Frame::decode_payload(HELLO, &[0; 5]).unwrap_err();
        assert!(matches!(err, WispError::BufferUnderflow));
    }

    #[test]
    fn hello_trailing_bytes_rejected() {
        // Valid HELLO with auth, then one extra byte.
        let frame = Frame::Hello {
            max_control_payload: 65536,
            max_data_payload: 1028,
            max_m_log2: 20,
            max_symbols: 65536,
            profiles: vec![(1, 0)],
            auth: Some(HelloAuth::PskHmac { nonce: [0xBB; 32] }),
        };
        let mut payload = frame.encode_payload();
        payload.push(0xFF); // extra trailing byte
        let err = Frame::decode_payload(HELLO, &payload).unwrap_err();
        assert!(matches!(err, WispError::TrailingBytes));
    }

    #[test]
    fn hello_unknown_auth_mode_rejected() {
        // Valid HELLO structure but with an unknown auth_mode byte.
        let frame = Frame::Hello {
            max_control_payload: 65536,
            max_data_payload: 1028,
            max_m_log2: 20,
            max_symbols: 65536,
            profiles: vec![(1, 0)],
            auth: None,
        };
        let mut payload = frame.encode_payload();
        // Append a fake auth trailer with unknown mode 0xFF.
        payload.push(0xFF);
        payload.extend_from_slice(&[0xAA; 32]);
        let err = Frame::decode_payload(HELLO, &payload).unwrap_err();
        assert!(matches!(err, WispError::InvalidAuthMode(0xFF)));
    }

    #[test]
    fn hello_truncated_auth_trailer_rejected() {
        // Valid HELLO with partial auth trailer (not enough bytes for nonce).
        let frame = Frame::Hello {
            max_control_payload: 65536,
            max_data_payload: 1028,
            max_m_log2: 20,
            max_symbols: 65536,
            profiles: vec![(1, 0)],
            auth: None,
        };
        let mut payload = frame.encode_payload();
        // Append auth_mode byte but only 10 bytes of nonce (need 32).
        payload.push(crate::auth::AUTH_MODE_HMAC_SHA256);
        payload.extend_from_slice(&[0xAA; 10]);
        let err = Frame::decode_payload(HELLO, &payload).unwrap_err();
        assert!(matches!(err, WispError::BufferUnderflow));
    }

    #[test]
    fn truncated_plan_payload() {
        let err = Frame::decode_payload(PLAN, &[0; 10]).unwrap_err();
        assert!(matches!(err, WispError::BufferUnderflow));
    }

    #[test]
    fn truncated_fork_payload() {
        let err = Frame::decode_payload(FORK, &[0; 30]).unwrap_err();
        assert!(matches!(err, WispError::BufferUnderflow));
    }
}
