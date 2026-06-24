use criterion::{black_box, criterion_group, criterion_main, Criterion};
use kinetic_vdf::ChiaVdfEngine;
use kinetic_core::traits::VdfEngine;
use kinetic_core::types::{Commitment, VdfProof};

fn bench_vdf(c: &mut Criterion) {
    let engine = ChiaVdfEngine::new();
    let challenge = Commitment {
        hash: [0u8; 32],
    };
    let iterations = 10_000; // Small iterations for fast benchmark

    let mut group = c.benchmark_group("chia_vdf");
    group.sample_size(10); // Generating VDF takes time
    
    group.bench_function("evaluate_10k", |b| {
        b.iter(|| {
            engine.evaluate(black_box(&challenge), black_box(iterations)).unwrap()
        })
    });

    let proof = engine.evaluate(&challenge, iterations).unwrap();
    
    group.bench_function("verify_10k", |b| {
        b.iter(|| {
            engine.verify(black_box(&challenge), black_box(&proof), black_box(iterations)).unwrap()
        })
    });
    
    group.finish();
}

criterion_group!(benches, bench_vdf);
criterion_main!(benches);
