#![no_main]
use libfuzzer_sys::fuzz_target;
use wisp_core::types::HEADER_SIZE;

fuzz_target!(|data: &[u8]| {
    if data.len() >= HEADER_SIZE {
        let mut buf = [0u8; HEADER_SIZE];
        buf.copy_from_slice(&data[..HEADER_SIZE]);
        let _ = wisp_core::frame::FrameHeader::decode(&buf);
    }
});
