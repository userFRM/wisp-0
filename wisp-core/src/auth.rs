use sha2::{Sha256, Digest};

/// HMAC block size for SHA-256.
const BLOCK_SIZE: usize = 64;

/// Compute HMAC-SHA256 per RFC 2104. Zero-alloc, no_std compatible.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut key_block = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        let h: [u8; 32] = Sha256::digest(key).into();
        key_block[..32].copy_from_slice(&h);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; BLOCK_SIZE];
    let mut opad = [0x5cu8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        ipad[i] ^= key_block[i];
        opad[i] ^= key_block[i];
    }

    // inner = SHA256(ipad || data)
    let inner: [u8; 32] = {
        let mut hasher = Sha256::new();
        hasher.update(ipad);
        hasher.update(data);
        hasher.finalize().into()
    };

    // outer = SHA256(opad || inner)
    let mut hasher = Sha256::new();
    hasher.update(opad);
    hasher.update(inner);
    hasher.finalize().into()
}

/// Compute a 16-byte HMAC-SHA256-128 tag over header || payload.
pub fn compute_tag(key: &[u8; 32], header: &[u8], payload: &[u8]) -> [u8; 16] {
    let mut msg = alloc::vec::Vec::with_capacity(header.len() + payload.len());
    msg.extend_from_slice(header);
    msg.extend_from_slice(payload);
    let full = hmac_sha256(key, &msg);
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&full[..16]);
    tag
}

/// Verify a 16-byte HMAC-SHA256-128 tag. Constant-time comparison.
pub fn verify_tag(key: &[u8; 32], header: &[u8], payload: &[u8], tag: &[u8; 16]) -> bool {
    let expected = compute_tag(key, header, payload);
    ct_eq(&expected, tag)
}

/// Derive a per-session key from PSK and nonces.
///
/// `session_key = HMAC-SHA256(psk, "WISP0" || nonce_initiator || nonce_responder || session_id_LE)`
pub fn derive_session_key(
    psk: &[u8],
    nonce_i: &[u8; 32],
    nonce_r: &[u8; 32],
    session_id: u64,
) -> [u8; 32] {
    let sid = session_id.to_le_bytes();
    let mut data = alloc::vec::Vec::with_capacity(5 + 32 + 32 + 8);
    data.extend_from_slice(b"WISP0");
    data.extend_from_slice(nonce_i);
    data.extend_from_slice(nonce_r);
    data.extend_from_slice(&sid);
    hmac_sha256(psk, &data)
}

/// Constant-time equality comparison for 16-byte slices.
fn ct_eq(a: &[u8; 16], b: &[u8; 16]) -> bool {
    let mut diff = 0u8;
    for i in 0..16 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Auth mode byte for HELLO payload: HMAC-SHA256-128 (legacy, deprecated).
pub const AUTH_MODE_HMAC_SHA256: u8 = 0x01;

/// Auth mode byte for HELLO payload: X25519 + PSK + HKDF-SHA256.
pub const AUTH_MODE_X25519_PSK: u8 = 0x02;

// ---------------------------------------------------------------------------
// HKDF-SHA256 (RFC 5869)
// ---------------------------------------------------------------------------

/// HKDF-Extract: PRK = HMAC-SHA256(salt, IKM).
pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    hmac_sha256(salt, ikm)
}

/// HKDF-Expand: derive `okm_len` bytes from PRK and info.
/// Panics if `okm_len > 255 * 32`.
pub fn hkdf_expand(prk: &[u8; 32], info: &[u8], okm_len: usize) -> alloc::vec::Vec<u8> {
    assert!(okm_len <= 255 * 32, "HKDF-Expand: OKM too large");
    let n = okm_len.div_ceil(32);
    let mut okm = alloc::vec::Vec::with_capacity(okm_len);
    let mut t_prev: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    for i in 1..=n {
        let mut input = alloc::vec::Vec::with_capacity(t_prev.len() + info.len() + 1);
        input.extend_from_slice(&t_prev);
        input.extend_from_slice(info);
        input.push(i as u8);
        let t_i = hmac_sha256(prk, &input);
        t_prev = t_i.to_vec();
        okm.extend_from_slice(&t_i);
    }
    okm.truncate(okm_len);
    okm
}

/// Derive session key from X25519 DH shared secret + PSK via HKDF.
///
/// Extract: `PRK = HKDF-Extract("WISP0-X25519", dh_shared || psk)`
/// Expand:  `key = HKDF-Expand(PRK, "WISP0-session" || nonce_i || nonce_r || session_id_LE, 32)`
pub fn derive_session_key_x25519(
    dh_shared: &[u8; 32],
    psk: &[u8],
    nonce_i: &[u8; 32],
    nonce_r: &[u8; 32],
    session_id: u64,
) -> [u8; 32] {
    let mut ikm = alloc::vec::Vec::with_capacity(32 + psk.len());
    ikm.extend_from_slice(dh_shared);
    ikm.extend_from_slice(psk);
    let prk = hkdf_extract(b"WISP0-X25519", &ikm);

    let sid = session_id.to_le_bytes();
    let mut info = alloc::vec::Vec::with_capacity(13 + 32 + 32 + 8);
    info.extend_from_slice(b"WISP0-session");
    info.extend_from_slice(nonce_i);
    info.extend_from_slice(nonce_r);
    info.extend_from_slice(&sid);
    let okm = hkdf_expand(&prk, &info, 32);
    let mut key = [0u8; 32];
    key.copy_from_slice(&okm);
    key
}

/// Compute an 8-byte key_id from a PSK: SHA-256(PSK)[0..8].
/// Used in HELLO auth trailer for keyring lookup.
pub fn compute_key_id(psk: &[u8]) -> [u8; 8] {
    let hash: [u8; 32] = Sha256::digest(psk).into();
    let mut kid = [0u8; 8];
    kid.copy_from_slice(&hash[..8]);
    kid
}

// ---------------------------------------------------------------------------
// X25519 Diffie-Hellman
// ---------------------------------------------------------------------------

/// Perform X25519 Diffie-Hellman. Returns 32-byte shared secret.
/// Caller must zeroize `secret_bytes` after use.
pub fn x25519_dh(secret_bytes: &[u8; 32], peer_pub_bytes: &[u8; 32]) -> [u8; 32] {
    let secret = x25519_dalek::StaticSecret::from(*secret_bytes);
    let peer_pub = x25519_dalek::PublicKey::from(*peer_pub_bytes);
    *secret.diffie_hellman(&peer_pub).as_bytes()
}

/// Compute X25519 public key from secret key.
pub fn x25519_public_key(secret_bytes: &[u8; 32]) -> [u8; 32] {
    let secret = x25519_dalek::StaticSecret::from(*secret_bytes);
    *x25519_dalek::PublicKey::from(&secret).as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 4231 Test Case 2: HMAC-SHA256 with "Jefe" key and "what do ya want for nothing?" data.
    #[test]
    fn hmac_sha256_rfc4231_case2() {
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let result = hmac_sha256(key, data);
        let expected: [u8; 32] = [
            0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e,
            0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7,
            0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83,
            0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43,
        ];
        assert_eq!(result, expected);
    }

    // RFC 4231 Test Case 1: key = 0x0b repeated 20 times, data = "Hi There".
    #[test]
    fn hmac_sha256_rfc4231_case1() {
        let key = [0x0bu8; 20];
        let data = b"Hi There";
        let result = hmac_sha256(&key, data);
        let expected: [u8; 32] = [
            0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53,
            0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
            0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7,
            0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7,
        ];
        assert_eq!(result, expected);
    }

    #[test]
    fn tag_round_trip() {
        let key = [0xABu8; 32];
        let header = [1u8; 80];
        let payload = [2u8; 100];
        let tag = compute_tag(&key, &header, &payload);
        assert!(verify_tag(&key, &header, &payload, &tag));
    }

    #[test]
    fn tag_rejects_tampered() {
        let key = [0xCDu8; 32];
        let header = [3u8; 80];
        let payload = [4u8; 50];
        let tag = compute_tag(&key, &header, &payload);
        let mut bad_payload = payload;
        bad_payload[0] ^= 1;
        assert!(!verify_tag(&key, &header, &bad_payload, &tag));
    }

    #[test]
    fn tag_rejects_wrong_key() {
        let key = [0xEFu8; 32];
        let header = [5u8; 80];
        let payload = [6u8; 64];
        let tag = compute_tag(&key, &header, &payload);
        let wrong_key = [0x01u8; 32];
        assert!(!verify_tag(&wrong_key, &header, &payload, &tag));
    }

    #[test]
    fn derive_session_key_deterministic() {
        let psk = b"my-secret";
        let nonce_i = [0x11u8; 32];
        let nonce_r = [0x22u8; 32];
        let sid = 0xDEADBEEF;
        let k1 = derive_session_key(psk, &nonce_i, &nonce_r, sid);
        let k2 = derive_session_key(psk, &nonce_i, &nonce_r, sid);
        assert_eq!(k1, k2);
    }

    #[test]
    fn derive_session_key_differs_with_nonce() {
        let psk = b"my-secret";
        let nonce_i = [0x11u8; 32];
        let nonce_r1 = [0x22u8; 32];
        let nonce_r2 = [0x33u8; 32];
        let sid = 42;
        let k1 = derive_session_key(psk, &nonce_i, &nonce_r1, sid);
        let k2 = derive_session_key(psk, &nonce_i, &nonce_r2, sid);
        assert_ne!(k1, k2);
    }

    #[test]
    fn constant_time_eq_works() {
        let a = [1u8; 16];
        let b = [1u8; 16];
        let c = [2u8; 16];
        assert!(ct_eq(&a, &b));
        assert!(!ct_eq(&a, &c));
    }

    // -- HKDF tests (RFC 5869 Test Case 1) --

    #[test]
    fn hkdf_rfc5869_case1() {
        let ikm = [0x0bu8; 22];
        let salt: [u8; 13] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let info: [u8; 10] = [
            0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9,
        ];
        let prk = hkdf_extract(&salt, &ikm);
        let expected_prk: [u8; 32] = [
            0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf,
            0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b, 0xba, 0x63,
            0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31,
            0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2, 0xb3, 0xe5,
        ];
        assert_eq!(prk, expected_prk);

        let okm = hkdf_expand(&prk, &info, 42);
        let expected_okm: [u8; 42] = [
            0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a,
            0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
            0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c,
            0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf,
            0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18,
            0x58, 0x65,
        ];
        assert_eq!(okm.as_slice(), &expected_okm);
    }

    // -- X25519 key derivation tests --

    #[test]
    fn derive_session_key_x25519_deterministic() {
        let dh = [0x42u8; 32];
        let psk = b"test-psk";
        let ni = [0x11u8; 32];
        let nr = [0x22u8; 32];
        let k1 = derive_session_key_x25519(&dh, psk, &ni, &nr, 1);
        let k2 = derive_session_key_x25519(&dh, psk, &ni, &nr, 1);
        assert_eq!(k1, k2);
    }

    #[test]
    fn derive_session_key_x25519_differs_with_dh() {
        let psk = b"test";
        let ni = [0x11u8; 32];
        let nr = [0x22u8; 32];
        let k1 = derive_session_key_x25519(&[0x01; 32], psk, &ni, &nr, 1);
        let k2 = derive_session_key_x25519(&[0x02; 32], psk, &ni, &nr, 1);
        assert_ne!(k1, k2);
    }

    // -- key_id tests --

    #[test]
    fn compute_key_id_deterministic() {
        let k1 = compute_key_id(b"secret-a");
        let k2 = compute_key_id(b"secret-a");
        assert_eq!(k1, k2);
    }

    #[test]
    fn compute_key_id_differs_for_different_psks() {
        let k1 = compute_key_id(b"secret-a");
        let k2 = compute_key_id(b"secret-b");
        assert_ne!(k1, k2);
    }

    // -- X25519 DH tests --

    #[test]
    fn x25519_dh_commutativity() {
        // a's secret, b's secret (arbitrary but deterministic)
        let a_secret = [0x77u8; 32];
        let b_secret = [0x88u8; 32];
        let a_pub = x25519_public_key(&a_secret);
        let b_pub = x25519_public_key(&b_secret);
        let shared_ab = x25519_dh(&a_secret, &b_pub);
        let shared_ba = x25519_dh(&b_secret, &a_pub);
        assert_eq!(shared_ab, shared_ba);
    }

    #[test]
    fn x25519_different_keys_different_shared() {
        let a_secret = [0x01u8; 32];
        let b_secret = [0x02u8; 32];
        let c_secret = [0x03u8; 32];
        let a_pub = x25519_public_key(&a_secret);
        let shared_ba = x25519_dh(&b_secret, &a_pub);
        let shared_ca = x25519_dh(&c_secret, &a_pub);
        assert_ne!(shared_ba, shared_ca);
    }
}
