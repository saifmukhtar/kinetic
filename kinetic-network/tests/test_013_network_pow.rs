use kinetic_network::pow::{is_valid_sybil_pow, mine_sybil_keypair};
use kinetic_network::NetworkEventLoop;
use libp2p::PeerId;

#[test]
fn test_pow_difficulty_1() {
    let difficulty = 1;
    let pulse = 10000;

    let keypair = mine_sybil_keypair(pulse, difficulty);
    let peer_id = PeerId::from(keypair.public());
    assert!(is_valid_sybil_pow(&peer_id, pulse, difficulty));
}

#[test]
fn test_pow_difficulty_2() {
    let difficulty = 2;
    let pulse = 20000;

    let keypair = mine_sybil_keypair(pulse, difficulty);
    let peer_id = PeerId::from(keypair.public());
    assert!(is_valid_sybil_pow(&peer_id, pulse, difficulty));
}

#[test]
fn test_pow_invalid_nonce() {
    let difficulty = 2;
    let pulse = 20000;

    let keypair = mine_sybil_keypair(pulse, difficulty);
    let peer_id = PeerId::from(keypair.public());

    // Check against completely wrong pulse
    assert!(!is_valid_sybil_pow(&peer_id, pulse + 100000, difficulty));
}

#[test]
fn test_pow_invalid_payload() {
    let difficulty = 2;
    let pulse = 20000;

    let keypair = mine_sybil_keypair(pulse, difficulty);
    let _peer_id = PeerId::from(keypair.public());

    // Generate another peer
    let tampered_keypair = libp2p::identity::Keypair::generate_ed25519();
    let tampered_peer = PeerId::from(tampered_keypair.public());

    assert!(!is_valid_sybil_pow(&tampered_peer, pulse, difficulty));
}

#[test]
fn test_xor_tie_breaker_different_payloads() {
    let p1 = vec![1, 2, 3];
    let p2 = vec![4, 5, 6];

    let winner =
        NetworkEventLoop::xor_tie_breaker("test_query", vec![p1.clone(), p2.clone()], 12345);

    assert!(winner.is_some());
    let winner_payload = winner.unwrap();
    assert!(winner_payload == p1 || winner_payload == p2);
}

#[test]
fn test_xor_tie_breaker_single_payload() {
    let p1 = vec![1, 2, 3];

    let winner = NetworkEventLoop::xor_tie_breaker("test_query", vec![p1.clone()], 12345);

    assert!(winner.is_some());
    assert_eq!(winner.unwrap(), p1);
}
