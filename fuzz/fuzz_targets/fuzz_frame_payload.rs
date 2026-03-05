#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let frame_type = data[0];
    let payload = &data[1..];
    let _ = wisp_core::frame::Frame::decode_payload(frame_type, payload);
});
