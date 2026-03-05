#![no_main]
use libfuzzer_sys::fuzz_target;
use wisp_core::varint;

fuzz_target!(|data: &[u8]| {
    // Try decoding at offset 0.
    if let Ok((val, _next_off)) = varint::decode(data, 0) {
        // If decode succeeds, encode and verify round-trip.
        let mut buf = [0u8; 10];
        let len = varint::encode(val, &mut buf);
        if let Ok((val2, _)) = varint::decode(&buf[..len], 0) {
            assert_eq!(val, val2);
        }
    }

    // Try decoding at various offsets.
    for off in 1..data.len().min(8) {
        let _ = varint::decode(data, off);
    }
});
