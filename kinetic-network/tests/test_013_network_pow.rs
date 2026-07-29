use kinetic_network::pow::{is_valid_sybil_pow, mine_sybil_keypair};
use libp2p::PeerId;
#[test]
#[ignore = "simulation feature mocks PoW"]
fn test_pow_difficulty_1() {
    let difficulty = 1;
    let pulse = 10000;

    let keypair = mine_sybil_keypair(pulse, difficulty);
    let peer_id = PeerId::from(keypair.public());
    assert!(is_valid_sybil_pow(&peer_id, pulse, difficulty));
}

#[test]
#[ignore = "simulation feature mocks PoW"]
fn test_pow_difficulty_2() {
    let difficulty = 2;
    let pulse = 20000;

    let keypair = mine_sybil_keypair(pulse, difficulty);
    let peer_id = PeerId::from(keypair.public());
    assert!(is_valid_sybil_pow(&peer_id, pulse, difficulty));
}

#[test]
#[ignore = "simulation feature mocks PoW"]
fn test_pow_invalid_nonce() {
    let difficulty = 8;
    let pulse = 20000;

    let keypair = mine_sybil_keypair(pulse, difficulty);
    let peer_id = PeerId::from(keypair.public());

    // Check against wrong pulse. Since difficulty 8 has 1/256 chance of accidental match, loop.
    let mut wrong_pulse = pulse + 100000;
    while is_valid_sybil_pow(&peer_id, wrong_pulse, difficulty) {
        wrong_pulse += 100000;
    }
    assert!(!is_valid_sybil_pow(&peer_id, wrong_pulse, difficulty));
}

#[test]
#[ignore = "simulation feature mocks PoW"]
fn test_pow_invalid_payload() {
    let difficulty = 8;
    let pulse = 20000;

    let keypair = mine_sybil_keypair(pulse, difficulty);
    let _peer_id = PeerId::from(keypair.public());

    // Generate another peer
    let tampered_peer = loop {
        let tampered_keypair = libp2p::identity::Keypair::generate_ed25519();
        let p = PeerId::from(tampered_keypair.public());
        if !is_valid_sybil_pow(&p, pulse, difficulty) {
            break p;
        }
    };

    assert!(!is_valid_sybil_pow(&tampered_peer, pulse, difficulty));
}
