use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ed25519_dalek::{SigningKey, Signer, Verifier, Signature};
use getrandom::fill;

fn bench_ed25519(c: &mut Criterion) {
    let mut bytes = [0u8; 32];
    fill(&mut bytes).unwrap();
    let signing_key = SigningKey::from_bytes(&bytes);
    let verifying_key = signing_key.verifying_key();
    let message: &[u8] = b"This is a dummy heartbeat payload for benchmarking";

    let mut group = c.benchmark_group("ed25519_crypto");
    
    group.bench_function("sign", |b| {
        b.iter(|| signing_key.sign(black_box(message)))
    });

    let signature = signing_key.sign(message);
    
    group.bench_function("verify", |b| {
        b.iter(|| verifying_key.verify(black_box(message), black_box(&signature)))
    });
    
    group.finish();
}

criterion_group!(benches, bench_ed25519);
criterion_main!(benches);
