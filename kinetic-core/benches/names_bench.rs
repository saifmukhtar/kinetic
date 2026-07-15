use criterion::{criterion_group, criterion_main, Criterion};
use kinetic_core::types::names::{extract_apex_domain, is_valid_apex_name, normalize_name};
use std::hint::black_box;

fn bench_names(c: &mut Criterion) {
    let mut group = c.benchmark_group("names_processing");

    let raw_name = "Some-Wild-App.Kin.";

    group.bench_function("normalize_name", |b| {
        b.iter(|| normalize_name(black_box(raw_name)))
    });

    let norm_name = normalize_name(raw_name);

    group.bench_function("is_valid_apex_name", |b| {
        // is_valid_apex_name expects an un-normalized or normalized string, we'll pass normalized to measure purely logic
        b.iter(|| is_valid_apex_name(black_box(&norm_name)))
    });

    group.bench_function("extract_apex_domain", |b| {
        b.iter(|| extract_apex_domain(black_box(&norm_name)))
    });

    group.finish();
}

criterion_group!(benches, bench_names);
criterion_main!(benches);
