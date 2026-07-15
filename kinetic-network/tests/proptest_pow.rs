use kinetic_network::pow::is_valid_sybil_pow;
use libp2p::PeerId;
use proptest::prelude::*;

fn generate_random_peer_id() -> PeerId {
    let keypair = libp2p::identity::ed25519::Keypair::generate();
    let public = keypair.public();
    let identity = libp2p::identity::PublicKey::from(public);
    PeerId::from(identity)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    #[test]
    fn test_sybil_pow_does_not_panic(
        drand_pulse in any::<u64>(),
        difficulty in 0..=32u32
    ) {
        // Just verify it doesn't panic.
        // PeerId generation isn't natively fuzzed via proptest simply,
        // but we can generate a random one or use a dummy buffer for hashing.
        let peer_id = generate_random_peer_id();
        let _ = is_valid_sybil_pow(&peer_id, drand_pulse, difficulty);
    }
}
