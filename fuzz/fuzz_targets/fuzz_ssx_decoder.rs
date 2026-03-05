#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use wisp_core::ssx_decoder::SsxDecoder;
use wisp_core::types::SYMBOL_SIZE;

#[derive(Debug, Arbitrary)]
struct FuzzInput {
    n: u8,
    ops: Vec<Op>,
}

#[derive(Debug, Arbitrary)]
enum Op {
    Sym { k: u8, fill: u8 },
    Mix { t: u32, fill: u8 },
}

fuzz_target!(|input: FuzzInput| {
    let n = (input.n as usize).clamp(1, 64);
    let mut dec = SsxDecoder::new(n);

    for op in &input.ops {
        if dec.is_complete() {
            break;
        }
        match op {
            Op::Sym { k, fill } => {
                let k = (*k as usize) % n;
                let data = [*fill; SYMBOL_SIZE];
                dec.add_sym(k, data);
            }
            Op::Mix { t, fill } => {
                let data = [*fill; SYMBOL_SIZE];
                dec.add_mix(*t, data, 42, 0, 1);
            }
        }
    }
    // Must not panic on any of these.
    let _ = dec.known_count();
    let _ = dec.is_complete();
});
