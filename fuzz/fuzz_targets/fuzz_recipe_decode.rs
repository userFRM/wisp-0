#![no_main]
use libfuzzer_sys::fuzz_target;
use wisp_core::recipe::Recipe;

fuzz_target!(|data: &[u8]| {
    if let Ok(recipe) = Recipe::decode_wire(data) {
        // If decoding succeeds, re-encode and verify round-trip doesn't panic.
        let wire = recipe.encode_wire();
        let _ = Recipe::decode_wire(&wire);
    }
});
