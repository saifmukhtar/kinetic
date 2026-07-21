use kinetic_network::pow::mine_sybil_keypair;
use std::time::Instant;

fn main() {
    println!("Benchmarking PoW Difficulty Generation...");
    println!("=========================================");

    let difficulties = vec![8, 16, 18, 20, 22, 24];

    for bits in difficulties {
        println!("Testing difficulty: {} bits", bits);
        let start = Instant::now();

        // This function generates the identity that meets the required bits (pulse 1 for testing)
        let _ = mine_sybil_keypair(1, bits);

        let elapsed = start.elapsed();
        println!("  -> Time taken: {:?}", elapsed);
        println!("-----------------------------------------");
    }

    println!("Done!");
}
