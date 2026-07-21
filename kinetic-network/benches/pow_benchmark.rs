use argon2::{Algorithm, Argon2, Params, Version};
use libp2p::identity::Keypair;
use std::time::{Duration, Instant};

fn compute_hash(argon2: &Argon2, peer_bytes: &[u8], epoch: u64) -> [u8; 32] {
    let mut hash = [0u8; 32];
    let salt = epoch.to_le_bytes();
    argon2
        .hash_password_into(peer_bytes, &salt, &mut hash)
        .expect("Hash should not fail");
    hash
}

fn leading_zeros(hash: &[u8; 32]) -> u32 {
    let mut zeros = 0;
    for &byte in hash {
        if byte == 0 {
            zeros += 8;
        } else {
            zeros += byte.leading_zeros();
            break;
        }
    }
    zeros
}

fn format_duration(seconds: f64) -> String {
    if seconds < 0.001 {
        format!("{:.2} µs", seconds * 1_000_000.0)
    } else if seconds < 1.0 {
        format!("{:.2} ms", seconds * 1000.0)
    } else if seconds < 60.0 {
        format!("{:.2} seconds", seconds)
    } else if seconds < 3600.0 {
        format!("{:.2} minutes", seconds / 60.0)
    } else if seconds < 86400.0 {
        format!("{:.2} hours", seconds / 3600.0)
    } else {
        format!("{:.2} days", seconds / 86400.0)
    }
}

fn main() {
    println!("========================================");
    println!(" Kinetic Sybil PoW Benchmark Projection ");
    println!("========================================\n");

    println!("Step 1: Benchmarking CPU Hashrate (10 Rounds of 60 seconds)...");
    
    // Exact params used in kinetic_network::pow::mine_sybil_keypair
    let params = Params::new(16384, 1, 1, None).expect("Valid static Argon2 params");
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    
    let keypair = Keypair::generate_ed25519();
    let peer_id = libp2p::PeerId::from(keypair.public());
    let peer_bytes = peer_id.to_bytes();
    
    let mut total_hashes = 0u64;
    let mut total_duration = 0.0;
    
    let num_rounds = 10;
    let round_duration = Duration::from_secs(60);
    
    for round in 1..=num_rounds {
        let mut round_hashes = 0u64;
        let start = Instant::now();
        
        while start.elapsed() < round_duration {
            // Hash repeatedly to measure throughput
            std::hint::black_box(compute_hash(&argon2, &peer_bytes, round_hashes));
            round_hashes += 1;
        }
        
        let actual_round_duration = start.elapsed().as_secs_f64();
        let round_hps = round_hashes as f64 / actual_round_duration;
        
        total_hashes += round_hashes;
        total_duration += actual_round_duration;
        
        println!("Round {:2}/10: Completed {} hashes in {:.2}s -> {:.2} H/s", 
                 round, round_hashes, actual_round_duration, round_hps);
    }
    
    let average_hps = total_hashes as f64 / total_duration;
    
    println!("\n=== BENCHMARK RESULTS ===");
    println!("Total Hashes: {}", total_hashes);
    println!("Total Time: {:.2}s", total_duration);
    println!("Average CPU Hashrate: {:.2} H/s\n", average_hps);
    
    println!("Step 2: Mathematical Projection for Difficulty Bits");
    println!("{:<10} | {:<20} | {:<20}", "Difficulty", "Expected Hashes", "Expected Time");
    println!("---------------------------------------------------------------");
    
    let bit_levels = [8, 10, 12, 14, 16, 18, 20, 22, 24];
    
    for &bits in &bit_levels {
        let expected_hashes = 2f64.powi(bits as i32);
        let expected_time = expected_hashes / average_hps;
        println!("{:<10} | {:<20.0} | {:<20}", bits, expected_hashes, format_duration(expected_time));
    }
    
    println!("\nBenchmark Complete.");
}
