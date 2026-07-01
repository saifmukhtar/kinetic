use ed25519_dalek::{Signer, SigningKey};
use kinetic_core::traits::VdfEngine;
use kinetic_core::types::{Commitment, Reveal};
use kinetic_network::event_loop::NetworkEventLoop;
use kinetic_vdf::ChiaVdfEngine;
use rand_core::OsRng;
use sha2::{Digest, Sha256};

#[test]
fn test_010_xor_eclipse() {
    let mut csprng = OsRng;
    let keypair = SigningKey::generate(&mut csprng);
    let pubkey = keypair.verifying_key();

    let drand_pulse = 50u64;
    let mut pulse_bytes = [0u8; 32];
    pulse_bytes[..8].copy_from_slice(&drand_pulse.to_be_bytes());

    let drand_randomness = hex::encode(pulse_bytes);

    let name = "alice.kin";
    let iterations = 1; // 1 iteration for fast test

    // Generate REAL VDF Proof
    let mut hasher = Sha256::new();
    hasher.update(name.as_bytes());
    hasher.update([0u8; 32]);
    hasher.update(pulse_bytes);
    hasher.update(pubkey.as_bytes());
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&hasher.finalize());

    let challenge = Commitment { hash };
    let engine = ChiaVdfEngine::new();
    let real_vdf_proof = engine.evaluate(&challenge, iterations).unwrap();

    let mut real_reveal = Reveal {
        name: name.to_string(),
        salt: [0u8; 32],
        drand_randomness: drand_randomness.clone(),
        drand_pulse,
        iterations,
        vdf_proof: real_vdf_proof,
        pubkey: pubkey.to_bytes().to_vec(),
        signature: vec![],
        protocol_version: 1,
        payload: vec![],
    };
    real_reveal.signature = keypair
        .sign(&real_reveal.signable_bytes())
        .to_bytes()
        .to_vec();

    // Generate FAKE payload with proof bytes matching the pulse exactly (so XOR = 0)
    // but the VDF is invalid.
    let mut fake_reveal = real_reveal.clone();
    fake_reveal.vdf_proof.proof_bytes = pulse_bytes.to_vec(); // will xor to 0, which is perfectly close
                                                              // re-sign so signature is valid
    fake_reveal.signature = keypair
        .sign(&fake_reveal.signable_bytes())
        .to_bytes()
        .to_vec();

    let real_bytes = serde_json::to_vec(&real_reveal).unwrap();
    let fake_bytes = serde_json::to_vec(&fake_reveal).unwrap();

    let winner = NetworkEventLoop::xor_tie_breaker(
        name,
        vec![real_bytes.clone(), fake_bytes.clone()],
        drand_pulse,
    );

    // The tie breaker should pick the REAL bytes, because the fake bytes fail VDF verification.
    assert_eq!(
        winner.unwrap(),
        real_bytes,
        "SECURITY FLAW: Fake payload won tie-breaker! Eclipse successful!"
    );
}
