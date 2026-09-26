use kinetic_kyn::types::Kyn;
use kinetic_network::challenge::solve_p2p_challenge;
use std::time::Instant;

fn main() {
    println!("Benchmarking peer challenge Difficulty Generation...");
    println!("=========================================");

    let difficulties = vec![8, 16, 18, 20, 22, 24];

    for bits in difficulties {
        println!("Testing difficulty: {} bits", bits);
        let start = Instant::now();

        // This function generates the identity that meets the required bits (kyn 1 for testing)
        let _ = solve_p2p_challenge(Kyn(1), bits);

        let elapsed = start.elapsed();
        println!("  -> Time taken: {:?}", elapsed);
        println!("-----------------------------------------");
    }

    println!("Done!");
}
