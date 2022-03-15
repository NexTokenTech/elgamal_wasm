use criterion::{criterion_group, criterion_main, Criterion};
use elgamal_wasm::generic::PublicKey;
use elgamal_wasm::{KeyFormat, KeyGenerator};
use num_bigint::BigInt;
mod profiler;
use profiler::FlameGraphProfiler;
use std::time::Duration;

fn pubkey_gen_benchmark(bit_length: u32) {
    let mut pub_key: PublicKey<BigInt> =
        PublicKey::from_hex_str("0x747c85d7, 0x747c85d6, 0xb2040843, 32");
    for _ in 0..10 {
        pub_key = pub_key.yield_pubkey(bit_length);
    }
}

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("pubkey-gen-benchmark");
    group
        .significance_level(0.1)
        .measurement_time(Duration::from_secs(20));
    group.bench_function("pubkey gen small x10", |b| {
        b.iter(|| pubkey_gen_benchmark(64))
    });
    group.bench_function("pubkey gen middle x10", |b| {
        b.iter(|| pubkey_gen_benchmark(128))
    });
    group.finish();
}

criterion_group!(
    name = benches;
    config = Criterion::default().with_profiler(FlameGraphProfiler::new(100));
    targets = criterion_benchmark
);
criterion_main!(benches);
