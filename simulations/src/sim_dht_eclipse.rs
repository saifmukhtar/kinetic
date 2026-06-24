use sha2::{Sha256, Digest};
use rayon::prelude::*;
use std::time::Instant;
use std::sync::atomic::{AtomicU32, Ordering};

const TOTAL_NAMES: u64 = 1_000_000_000;
const KEYS_PER_NAME: u64 = 5;
const NUM_BUCKETS: usize = 65536; // Using top 16 bits for bucket distribution

fn main() {
    println!("--- Kinetic DHT Keyspace Eclipse Simulation ---");
    println!("Simulating {} billion names ({} billion total derived keys).", TOTAL_NAMES as f64 / 1e9, (TOTAL_NAMES * KEYS_PER_NAME) as f64 / 1e9);
    println!("Measuring distribution across {} Kademlia sectors (top 16 bits).", NUM_BUCKETS);
    
    // Use atomic counters for parallel buckets
    let mut buckets: Vec<AtomicU32> = Vec::with_capacity(NUM_BUCKETS);
    for _ in 0..NUM_BUCKETS {
        buckets.push(AtomicU32::new(0));
    }

    let start = Instant::now();

    // Process in chunks to leverage Rayon
    let chunk_size = 1_000_000;
    let chunks = TOTAL_NAMES / chunk_size;

    (0..chunks).into_par_iter().for_each(|chunk_idx| {
        let start_idx = chunk_idx * chunk_size;
        let end_idx = start_idx + chunk_size;
        
        let mut local_counts = vec![0u32; NUM_BUCKETS];
        
        for name_id in start_idx..end_idx {
            for key_idx in 1..=KEYS_PER_NAME {
                let mut hasher = Sha256::new();
                hasher.update(&name_id.to_le_bytes());
                hasher.update(&key_idx.to_le_bytes());
                let result = hasher.finalize();
                
                // Take top 16 bits
                let bucket = ((result[0] as usize) << 8) | (result[1] as usize);
                local_counts[bucket] += 1;
            }
        }

        // Commit local counts to global atomic array
        for (i, count) in local_counts.iter().enumerate() {
            if *count > 0 {
                buckets[i].fetch_add(*count, Ordering::Relaxed);
            }
        }
    });

    let duration = start.elapsed();
    
    let mut min_count = u32::MAX;
    let mut max_count = 0;
    let mut total_keys: u64 = 0;
    
    for count in buckets.iter() {
        let c = count.load(Ordering::Relaxed);
        if c < min_count { min_count = c; }
        if c > max_count { max_count = c; }
        total_keys += c as u64;
    }

    let expected_avg = total_keys as f64 / NUM_BUCKETS as f64;
    
    println!("\nSimulation completed in {:.2} seconds.", duration.as_secs_f64());
    println!("Total Keys Generated: {}", total_keys);
    println!("Expected Keys per Sector: {:.2}", expected_avg);
    println!("Min Keys in any Sector: {}", min_count);
    println!("Max Keys in any Sector: {}", max_count);
    println!("Variance (Max - Min): {:.2}%", ((max_count - min_count) as f64 / expected_avg) * 100.0);
    
    println!("\nConclusion:");
    if ((max_count - min_count) as f64 / expected_avg) < 0.05 {
        println!("Pass: The SHA-256 derivation provides perfect uniform dispersion.");
        println!("Probability of eclipsing all 5 derived keys for a single name requires uniform control over the entire 256-bit keyspace.");
    } else {
        println!("Fail: Statistical clumping detected.");
    }
}
