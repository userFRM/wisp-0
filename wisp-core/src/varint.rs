use alloc::vec::Vec;

use crate::error::{Result, WispError};

/// Encode a u64 as ULEB128 into a buffer. Returns the number of bytes written.
pub fn encode(value: u64, buf: &mut [u8]) -> usize {
    let mut x = value;
    let mut i = 0;
    loop {
        let byte = (x & 0x7F) as u8;
        x >>= 7;
        if x != 0 {
            buf[i] = byte | 0x80;
        } else {
            buf[i] = byte;
            return i + 1;
        }
        i += 1;
    }
}

/// Encode a u64 as ULEB128, appending to a Vec.
pub fn encode_vec(value: u64, out: &mut Vec<u8>) {
    let mut x = value;
    loop {
        let byte = (x & 0x7F) as u8;
        x >>= 7;
        if x != 0 {
            out.push(byte | 0x80);
        } else {
            out.push(byte);
            return;
        }
    }
}

/// Decode a ULEB128 value from a byte slice at the given offset.
/// Returns (value, new_offset).
pub fn decode(buf: &[u8], mut off: usize) -> Result<(u64, usize)> {
    let mut x: u64 = 0;
    let mut shift: u32 = 0;
    loop {
        if off >= buf.len() {
            return Err(WispError::BufferUnderflow);
        }
        let b = buf[off];
        off += 1;
        x |= ((b & 0x7F) as u64) << shift;
        if (b & 0x80) == 0 {
            return Ok((x, off));
        }
        shift += 7;
        if shift > 63 {
            return Err(WispError::VarintOverflow);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let values = [0u64, 1, 127, 128, 255, 256, 16383, 16384, u64::MAX];
        for &v in &values {
            let mut buf = [0u8; 10];
            let n = encode(v, &mut buf);
            let (decoded, consumed) = decode(&buf, 0).unwrap();
            assert_eq!(decoded, v, "round-trip failed for {v}");
            assert_eq!(consumed, n);
        }
    }

    #[test]
    fn encode_known_values() {
        // 0 => [0x00]
        let mut buf = [0u8; 10];
        assert_eq!(encode(0, &mut buf), 1);
        assert_eq!(buf[0], 0x00);

        // 127 => [0x7F]
        assert_eq!(encode(127, &mut buf), 1);
        assert_eq!(buf[0], 0x7F);

        // 128 => [0x80, 0x01]
        assert_eq!(encode(128, &mut buf), 2);
        assert_eq!(&buf[..2], &[0x80, 0x01]);

        // 624485 => [0xE5, 0x8E, 0x26]
        assert_eq!(encode(624485, &mut buf), 3);
        assert_eq!(&buf[..3], &[0xE5, 0x8E, 0x26]);
    }

    #[test]
    fn encode_vec_matches() {
        let mut vec_buf = Vec::new();
        let mut arr_buf = [0u8; 10];
        for v in [0, 1, 128, 16384, u64::MAX] {
            vec_buf.clear();
            encode_vec(v, &mut vec_buf);
            let n = encode(v, &mut arr_buf);
            assert_eq!(&vec_buf[..], &arr_buf[..n]);
        }
    }
}
