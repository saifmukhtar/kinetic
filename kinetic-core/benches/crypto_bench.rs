use criterion::{Criterion, criterion_group, criterion_main};
use ed25519_dalek::{Signer as EdSigner, SigningKey as EdSigningKey, Verifier as EdVerifier};
use getrandom::getrandom;
use ml_dsa::signature::{Signer as MlSigner, Verifier as MlVerifier};
use ml_dsa::{Generate, Keypair, MlDsa65, SigningKey as MlSigningKey};
use std::hint::black_box;

fn bench_ed25519(c: &mut Criterion) {
    let mut bytes = [0u8; 32];
    getrandom(&mut bytes).unwrap();
    let signing_key = EdSigningKey::from_bytes(&bytes);
    let verifying_key = signing_key.verifying_key();
    let message: &[u8] = b"This is a dummy heartbeat payload for benchmarking";

    let mut group = c.benchmark_group("ed25519_crypto");

    group.bench_function("sign", |b| b.iter(|| signing_key.sign(black_box(message))));

    let signature = signing_key.sign(message);

    group.bench_function("verify", |b| {
        b.iter(|| verifying_key.verify(black_box(message), black_box(&signature)))
    });

    group.finish();
}

fn bench_mldsa65(c: &mut Criterion) {
    let signing_key = MlSigningKey::<MlDsa65>::generate();
    let verifying_key = signing_key.verifying_key();
    let message: &[u8] =
        b"This is a dummy heartbeat payload for benchmarking post-quantum ML-DSA-65";

    let mut group = c.benchmark_group("mldsa65_crypto");

    group.bench_function("sign", |b| b.iter(|| signing_key.sign(black_box(message))));

    let signature = signing_key.sign(message);

    group.bench_function("verify", |b| {
        b.iter(|| verifying_key.verify(black_box(message), black_box(&signature)))
    });

    group.finish();
}

criterion_group!(benches, bench_ed25519, bench_mldsa65);
criterion_main!(benches);
