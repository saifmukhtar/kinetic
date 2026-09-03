use ed25519_dalek::{Signer, SigningKey};
use kinetic_core::traits::VdfEngine;
use kinetic_core::types::Reveal;
use kinetic_network::event_loop::NetworkEventLoop;
use kinetic_vdf_rsa::RsaVdfEngine;

#[test]
#[ignore = "Slow cryptographic test: takes >60s to compute VDF proof"]
fn test_xor_eclipse_routing() {
    let keypair = SigningKey::from_bytes(&[1u8; 32]);
    let pubkey = keypair.verifying_key();

    let kyn = 50u64;
    let mut kyn_bytes = [0u8; 32];
    kyn_bytes[..8].copy_from_slice(&kyn.to_be_bytes());

    let drand_signature = hex::encode(kyn_bytes);

    let name = "thisisaverylongnamethatisverycheap.kin";
    let consensus_math = kinetic_core::consensus_math::ConsensusParams::default();
    let iterations = consensus_math.iterations(name);

    // Generate REAL VDF Proof
    let challenge = kinetic_core::types::Commitment::derive(
        kinetic_core::constants::NETWORK_SALT,
        &name,
        &[0u8; 32],
        &kyn_bytes,
        pubkey.as_bytes(),
    );
    let engine = RsaVdfEngine::new();
    let real_vdf_proof = engine.evaluate(&challenge, iterations).unwrap();

    let mut real_reveal = Reveal {
        name: name.to_string(),
        salt: [0u8; 32],
        drand_signature: drand_signature.clone(),
        kyn,
        iterations,
        vdf_proof: real_vdf_proof,
        pubkey: pubkey.to_bytes().to_vec(),
        signature: vec![],
        protocol_version: 1,
        payload: vec![],
        previous_proof: None,
        miner_pubkey: None,
        authorization: None,
    };
    real_reveal.signature = keypair
        .sign(&real_reveal.signable_bytes(kinetic_core::constants::NETWORK_SALT))
        .to_bytes()
        .to_vec();

    // Generate FAKE payload with proof bytes matching the kyn exactly (so XOR = 0)
    // but the VDF is invalid.
    let mut fake_reveal = real_reveal.clone();
    fake_reveal.vdf_proof.proof_bytes = kyn_bytes.to_vec(); // will xor to 0, which is perfectly close
    // re-sign so signature is valid
    fake_reveal.signature = keypair
        .sign(&fake_reveal.signable_bytes(kinetic_core::constants::NETWORK_SALT))
        .to_bytes()
        .to_vec();

    let real_bytes = serde_json::to_vec(&real_reveal).unwrap();
    let fake_bytes = serde_json::to_vec(&fake_reveal).unwrap();

    let winner =
        NetworkEventLoop::xor_tie_breaker(name, vec![real_bytes.clone(), fake_bytes.clone()], kyn);

    // The tie breaker should pick the REAL bytes, because the fake bytes fail VDF verification.
    assert_eq!(
        winner.unwrap(),
        real_bytes,
        "SECURITY FLAW: Fake payload won tie-breaker! Eclipse successful!"
    );
}
