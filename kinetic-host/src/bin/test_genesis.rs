use kinetic_core::consensus_math::ConsensusParams;
use kinetic_core::types::load_keypair;

fn main() {
    let keypair = load_keypair("host.key").unwrap();
    let pubkey = keypair.verifying_key().to_bytes();

    let params = ConsensusParams::default();
    let iters = params.required_iterations(
        "test.kin",
        0,
    );

    println!("Public Key: {:?}", pubkey);
    println!("Iterations for test.kin: {}", iters);
}
