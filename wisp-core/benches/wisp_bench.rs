use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use wisp_core::chunker;
use wisp_core::ict::Ict;
use wisp_core::ssx::{encode_mix, mix_indices, symbolize};
use wisp_core::ssx_decoder::SsxDecoder;
use wisp_core::types::{ChunkId, SYMBOL_SIZE};

/// Generate deterministic pseudo-random bytes.
fn pseudo_random(len: usize, seed: u64) -> Vec<u8> {
    (0..len)
        .map(|i| {
            let v = (i as u64).wrapping_mul(seed).wrapping_add(0x9E3779B97F4A7C15);
            (v >> 24) as u8
        })
        .collect()
}

/// Generate deterministic ChunkIds.
fn make_chunk_ids(count: usize) -> Vec<ChunkId> {
    (0..count)
        .map(|i| {
            let mut id = [0u8; 16];
            let bytes = (i as u64).to_le_bytes();
            id[..8].copy_from_slice(&bytes);
            id[8..].copy_from_slice(&bytes);
            ChunkId(id)
        })
        .collect()
}

// ---------------------------------------------------------------------------
// CDC Chunking
// ---------------------------------------------------------------------------

fn bench_cdc(c: &mut Criterion) {
    let mut group = c.benchmark_group("cdc_chunk");
    for &size in &[64 * 1024, 256 * 1024, 1024 * 1024, 4 * 1024 * 1024] {
        let data = pseudo_random(size, 0xDEADBEEF);
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::new("rabin", size), &data, |b, data| {
            b.iter(|| black_box(chunker::chunk(data)));
        });
        group.bench_with_input(BenchmarkId::new("gear", size), &data, |b, data| {
            b.iter(|| black_box(chunker::chunk_fast(data)));
        });
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// ICT Operations
// ---------------------------------------------------------------------------

fn bench_ict(c: &mut Criterion) {
    let mut group = c.benchmark_group("ict_cycle");
    for &n_keys in &[100, 500, 2000] {
        let all_keys = make_chunk_ids(n_keys);
        // Sender has all, receiver has 80%
        let have_count = n_keys * 4 / 5;
        let sender_keys = &all_keys[..];
        let receiver_keys = &all_keys[..have_count];

        group.bench_with_input(
            BenchmarkId::new("insert_subtract_peel", n_keys),
            &(sender_keys, receiver_keys),
            |b, (sender_keys, receiver_keys)| {
                b.iter(|| {
                    let d_est = sender_keys.len() - receiver_keys.len();
                    let mut sender_ict = Ict::with_estimated_missing(d_est.max(1));
                    for k in *sender_keys {
                        sender_ict.insert(k);
                    }
                    let mut recv_ict = Ict::new(sender_ict.m_log2);
                    for k in *receiver_keys {
                        recv_ict.insert(k);
                    }
                    let mut diff = sender_ict.subtract(&recv_ict).unwrap();
                    let missing = diff.peel().unwrap();
                    black_box(missing);
                });
            },
        );
    }
    group.finish();

    // Wire round-trip
    let mut group = c.benchmark_group("ict_wire");
    for &n_keys in &[100, 500, 2000] {
        let keys = make_chunk_ids(n_keys);
        let mut ict = Ict::with_estimated_missing(n_keys);
        for k in &keys {
            ict.insert(k);
        }
        let wire = ict.encode_wire();

        group.throughput(Throughput::Bytes(wire.len() as u64));
        group.bench_with_input(
            BenchmarkId::new("encode_decode", n_keys),
            &ict,
            |b, ict| {
                b.iter(|| {
                    let w = ict.encode_wire();
                    let decoded = Ict::decode_wire(&w).unwrap();
                    black_box(decoded);
                });
            },
        );
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// SSX Encoding
// ---------------------------------------------------------------------------

fn bench_ssx_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("ssx_encode");
    for &n in &[100, 500, 2000] {
        // Build source symbols from pseudo-random chunks
        let chunk_size = SYMBOL_SIZE; // 1 symbol per chunk
        let chunks: Vec<(ChunkId, Vec<u8>)> = (0..n)
            .map(|i| {
                let mut id = [0u8; 16];
                id[..8].copy_from_slice(&(i as u64).to_le_bytes());
                (ChunkId(id), pseudo_random(chunk_size, i as u64))
            })
            .collect();

        group.bench_with_input(BenchmarkId::new("symbolize", n), &chunks, |b, chunks| {
            b.iter(|| black_box(symbolize(chunks)));
        });

        // Mix encoding: generate 10 MIX symbols
        let symbols = symbolize(&chunks);
        let sym_refs: Vec<&[u8; SYMBOL_SIZE]> = symbols.iter().collect();
        group.bench_with_input(
            BenchmarkId::new("encode_10_mix", n),
            &sym_refs,
            |b, sym_refs| {
                b.iter(|| {
                    for t in 0u32..10 {
                        let (indices, _) = mix_indices(42, 0, 1, t, n as u32);
                        let mixed = encode_mix(sym_refs, &indices);
                        black_box(mixed);
                    }
                });
            },
        );
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// SSX Decoding
// ---------------------------------------------------------------------------

fn bench_ssx_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("ssx_decode");
    group.sample_size(20); // decoding is slower
    for &n in &[100, 500] {
        let chunks: Vec<(ChunkId, Vec<u8>)> = (0..n)
            .map(|i| {
                let mut id = [0u8; 16];
                id[..8].copy_from_slice(&(i as u64).to_le_bytes());
                (ChunkId(id), pseudo_random(SYMBOL_SIZE, i as u64))
            })
            .collect();
        let symbols = symbolize(&chunks);
        let sym_refs: Vec<&[u8; SYMBOL_SIZE]> = symbols.iter().collect();

        // Pre-compute MIX payloads
        let n_mix = (n as f64 * 0.15) as u32; // 15% overhead
        let mixes: Vec<(u32, [u8; SYMBOL_SIZE])> = (0..n_mix)
            .map(|t| {
                let (indices, _) = mix_indices(42, 0, 1, t, n as u32);
                (t, encode_mix(&sym_refs, &indices))
            })
            .collect();

        group.bench_with_input(
            BenchmarkId::new("full_decode", n),
            &(&symbols, &mixes),
            |b, (symbols, mixes)| {
                b.iter(|| {
                    let mut dec = SsxDecoder::new(symbols.len());
                    for (k, sym) in symbols.iter().enumerate() {
                        dec.add_sym(k, *sym);
                    }
                    for &(t, ref payload) in *mixes {
                        if dec.is_complete() {
                            break;
                        }
                        dec.add_mix(t, *payload, 42, 0, 1);
                    }
                    black_box(dec.known_count());
                });
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_cdc, bench_ict, bench_ssx_encode, bench_ssx_decode);
criterion_main!(benches);
