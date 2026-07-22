//! Command-line hardware benchmark utility for calibrating VDF iteration speeds.
//!
//! Measures CPU execution rate over 60-second rounds to determine the optimal
//! `benchmark_base_iterations` parameter for `network.json`.

use kinetic_core::traits::VdfEngine;
use kinetic_core::types::Commitment;
use kinetic_vdf::ChiaVdfEngine;
use std::time::Instant;

fn main() {
    println!("Starting Kinetic VDF Benchmark...");
    println!(
        "We will run the VDF for exactly 60 seconds to see how many iterations your CPU completes."
    );
    println!(
        "This will run multiple 60-second rounds to get an optimal average as you requested.\n"
    );

    let engine = ChiaVdfEngine::new();
    let challenge = Commitment { hash: [0u8; 32] };

    // Pick a small chunk of iterations so we can measure elapsed time frequently
    let chunk_size = 10_000;

    let rounds = 10;
    let mut total_iterations_per_minute = Vec::new();

    for round in 1..=rounds {
        println!(
            "Starting Round {}/{} (Running for 60 seconds...)",
            round, rounds
        );
        let start = Instant::now();
        let mut iterations = 0;

        while start.elapsed().as_secs() < 60 {
            // Evaluate chunk
            let _ = engine.evaluate(&challenge, chunk_size).expect("VDF failed");
            iterations += chunk_size;
        }

        let elapsed = start.elapsed().as_secs_f64();
        // Normalize exactly to 60.0 seconds just in case it overshot by a few milliseconds
        let normalized = (iterations as f64) * (60.0 / elapsed);
        let normalized_u64 = normalized as u64;

        println!(
            "Round {} completed: {} iterations in {:.2} seconds (~{} iterations/min)",
            round, iterations, elapsed, normalized_u64
        );

        total_iterations_per_minute.push(normalized_u64);
    }

    let sum: u64 = total_iterations_per_minute.iter().sum();
    let avg = sum / (rounds as u64);

    println!("\n=== BENCHMARK RESULTS ===");
    println!("Average iterations per minute: {}", avg);

    let target_minutes = kinetic_core::constants::BENCHMARK_TARGET_MINUTES;
    let target_iterations = avg * (target_minutes as u64);

    println!(
        "Based on your network.json target of {:.1} minutes:",
        target_minutes
    );
    println!(
        "Set \"benchmark_base_iterations\": {} in your network.json",
        target_iterations
    );
}
