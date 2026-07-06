use kinetic_core::consensus_math::ConsensusParams;
use kinetic_core::types::load_or_create_keypair;

fn main() {
    let keypair = load_or_create_keypair().unwrap();
    let pubkey = keypair.verifying_key().to_bytes();

    let params = ConsensusParams::default();
    let iters = params.required_iterations(
        &format!("{}{}", "test", kinetic_core::types::DOT_TLD),
        30070835,
        &pubkey,
    );

    println!("Public Key: {:?}", pubkey);
    println!(
        "Matches genesis? {}",
        pubkey == ConsensusParams::GENESIS_PUBKEY.unwrap()
    );
    println!("Iterations for test.kin: {}", iters);
}
