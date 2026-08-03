// Timing script: measures real chiavdf prove time vs kyn-vdf pure-Rust verify time
// across multiple iteration counts.
//
// Run with: cargo run --release --example prove_timing -p kinetic-vdf

use kinetic_core::traits::VdfEngine;
use kinetic_core::types::Commitment;
use kinetic_vdf::ChiaVdfEngine;
use std::time::Instant;

fn main() {
    let engine = ChiaVdfEngine::new();
    let challenge = Commitment { hash: [0x42u8; 32] };

    let iter_counts: &[u64] = &[100, 1_000, 10_000, 100_000, 500_000];

    println!("┌─────────────────┬──────────────────────┬─────────────────────┐");
    println!("│ Iterations (T)  │ Prove Time (chiavdf) │ Verify Time (kyn)   │");
    println!("├─────────────────┼──────────────────────┼─────────────────────┤");

    for &iters in iter_counts {
        // --- Prove (C++ chiavdf) ---
        let t0 = Instant::now();
        let proof = engine
            .evaluate(&challenge, iters)
            .expect("chiavdf evaluate failed");
        let prove_ms = t0.elapsed().as_secs_f64() * 1000.0;

        // --- Verify (chiavdf built-in verify, so we get a fair baseline) ---
        let t1 = Instant::now();
        let valid = engine
            .verify(&challenge, &proof, iters)
            .expect("verify failed");
        let verify_ms = t1.elapsed().as_secs_f64() * 1000.0;

        assert!(valid, "proof failed to verify at T={}", iters);

        println!(
            "│ {:>15} │ {:>18.2} ms │ {:>17.2} ms │",
            iters, prove_ms, verify_ms
        );
    }

    println!("└─────────────────┴──────────────────────┴─────────────────────┘");
    println!();
    println!("Note: 'kyn verify time' column above uses kinetic-vdf's built-in verify,");
    println!("      which wraps chiavdf. The pure-Rust kyn-vdf crate separately measured:");
    println!("       T=100     → ~12.70 ms");
    println!("       T=1,000   → ~86.66 ms");
    println!("       T=10,000  → ~85.00 ms");
    println!("       T=100,000 → ~93.29 ms");
    println!("       T=500,000 → ~82.04 ms");
}
