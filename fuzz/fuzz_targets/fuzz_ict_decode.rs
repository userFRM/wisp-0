#![no_main]
use libfuzzer_sys::fuzz_target;
use wisp_core::ict::Ict;

fuzz_target!(|data: &[u8]| {
    if let Ok(mut ict) = Ict::decode_wire(data) {
        // Skip very large tables to avoid OOM in the fuzzer.
        if ict.m_log2 > 16 {
            return;
        }
        // If decoding succeeds, try peeling — must not panic.
        let _ = ict.peel();
        // Re-encode and verify round-trip doesn't panic.
        let wire = ict.encode_wire();
        let _ = Ict::decode_wire(&wire);
    }
});
