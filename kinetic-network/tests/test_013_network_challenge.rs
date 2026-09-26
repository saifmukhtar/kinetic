use kinetic_kyn::types::Kyn;
use kinetic_network::challenge::{solve_p2p_challenge, verify_p2p_challenge};
use libp2p::PeerId;
#[test]
#[ignore = "simulation feature mocks PoW"]
fn test_challenge_difficulty_1() {
    let difficulty = 1;
    let kyn = 10000;

    let keypair = solve_p2p_challenge(Kyn(kyn), difficulty);
    let peer_id = PeerId::from(keypair.public());
    assert!(verify_p2p_challenge(&peer_id, Kyn(kyn), difficulty));
}

#[test]
#[ignore = "simulation feature mocks PoW"]
fn test_challenge_difficulty_2() {
    let difficulty = 2;
    let kyn = 20000;

    let keypair = solve_p2p_challenge(Kyn(kyn), difficulty);
    let peer_id = PeerId::from(keypair.public());
    assert!(verify_p2p_challenge(&peer_id, Kyn(kyn), difficulty));
}

#[test]
#[ignore = "simulation feature mocks PoW"]
fn test_challenge_invalid_nonce() {
    let difficulty = 8;
    let kyn = 20000;

    let keypair = solve_p2p_challenge(Kyn(kyn), difficulty);
    let peer_id = PeerId::from(keypair.public());

    // Check against wrong kyn. Since difficulty 8 has 1/256 chance of accidental match, loop.
    let mut wrong_kyn = kyn + 100000;
    while verify_p2p_challenge(&peer_id, Kyn(wrong_kyn), difficulty) {
        wrong_kyn += 100000;
    }
    assert!(!verify_p2p_challenge(&peer_id, Kyn(wrong_kyn), difficulty));
}

#[test]
#[ignore = "simulation feature mocks PoW"]
fn test_challenge_invalid_payload() {
    let difficulty = 8;
    let kyn = 20000;

    let keypair = solve_p2p_challenge(Kyn(kyn), difficulty);
    let _peer_id = PeerId::from(keypair.public());

    // Generate another peer
    let tampered_peer = loop {
        let tampered_keypair = libp2p::identity::Keypair::generate_ed25519();
        let p = PeerId::from(tampered_keypair.public());
        if !verify_p2p_challenge(&p, Kyn(kyn), difficulty) {
            break p;
        }
    };

    assert!(!verify_p2p_challenge(&tampered_peer, Kyn(kyn), difficulty));
}
