#![no_main]
use libfuzzer_sys::fuzz_target;
use wisp_core::recipe_ops;

fuzz_target!(|data: &[u8]| {
    let _ = recipe_ops::decode_ops(data);
});
