use kinetic_network::pow::{is_valid_sybil_pow, mine_sybil_keypair};
use libp2p::PeerId;
#[test]
#[ignore = "simulation feature mocks PoW"]
fn test_pow_difficulty_1() {
    let difficulty = 1;
    let kyn = 10000;

    let keypair = mine_sybil_keypair(kyn, difficulty);
    let peer_id = PeerId::from(keypair.public());
    assert!(is_valid_sybil_pow(&peer_id, kyn, difficulty));
}

#[test]
#[ignore = "simulation feature mocks PoW"]
fn test_pow_difficulty_2() {
    let difficulty = 2;
    let kyn = 20000;

    let keypair = mine_sybil_keypair(kyn, difficulty);
    let peer_id = PeerId::from(keypair.public());
    assert!(is_valid_sybil_pow(&peer_id, kyn, difficulty));
}

#[test]
#[ignore = "simulation feature mocks PoW"]
fn test_pow_invalid_nonce() {
    let difficulty = 8;
    let kyn = 20000;

    let keypair = mine_sybil_keypair(kyn, difficulty);
    let peer_id = PeerId::from(keypair.public());

    // Check against wrong kyn. Since difficulty 8 has 1/256 chance of accidental match, loop.
    let mut wrong_kyn = kyn + 100000;
    while is_valid_sybil_pow(&peer_id, wrong_kyn, difficulty) {
        wrong_kyn += 100000;
    }
    assert!(!is_valid_sybil_pow(&peer_id, wrong_kyn, difficulty));
}

#[test]
#[ignore = "simulation feature mocks PoW"]
fn test_pow_invalid_payload() {
    let difficulty = 8;
    let kyn = 20000;

    let keypair = mine_sybil_keypair(kyn, difficulty);
    let _peer_id = PeerId::from(keypair.public());

    // Generate another peer
    let tampered_peer = loop {
        let tampered_keypair = libp2p::identity::Keypair::generate_ed25519();
        let p = PeerId::from(tampered_keypair.public());
        if !is_valid_sybil_pow(&p, kyn, difficulty) {
            break p;
        }
    };

    assert!(!is_valid_sybil_pow(&tampered_peer, kyn, difficulty));
}
