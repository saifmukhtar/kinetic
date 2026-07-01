use base64::{engine::general_purpose::URL_SAFE_NO_PAD as b64_url, Engine};
use ed25519_dalek::SigningKey;
use kinetic_kid::{ControllerKey, KidDocument, KineticDid};
use rand_core::OsRng;
use sha2::{Digest, Sha256};

#[test]
fn test_013_kid_hijack() {
    // 1. Victim generates their identity
    let victim_key = SigningKey::generate(&mut OsRng);
    let victim_pub_b64 = b64_url.encode(victim_key.verifying_key().to_bytes());
    let mut hasher = Sha256::new();
    hasher.update(victim_key.verifying_key().to_bytes());
    let hash = hasher.finalize();
    let mut hex_hash = String::new();
    for byte in hash {
        use std::fmt::Write;
        write!(&mut hex_hash, "{:02x}", byte).unwrap();
    }
    let victim_did = format!("did:kin:{}", hex_hash);

    let mut doc = KidDocument {
        doc_type: "kinetic.kid.v1".to_string(),
        kid: KineticDid::new(&victim_did).unwrap(),
        created_at: 1000,
        pow_nonce: 0,
        controller_keys: vec![ControllerKey {
            id: format!("{}#primary", victim_did),
            key_type: "Ed25519".to_string(),
            public_key: victim_pub_b64,
        }],
        manifest: None,
        revocation_keys: vec![],
        signature: None,
    };
    doc.mine_pow();
    let victim_doc = doc.sign(&victim_key).unwrap();
    assert!(victim_doc.verify().is_ok());

    // 2. Attacker generates a random key and hijacks the victim's DID
    let attacker_key = SigningKey::generate(&mut OsRng);
    let attacker_pub_b64 = b64_url.encode(attacker_key.verifying_key().to_bytes());

    let mut forged_doc = KidDocument {
        doc_type: "kinetic.kid.v1".to_string(),
        kid: KineticDid::new(&victim_did).unwrap(), // Claiming victim's DID!
        created_at: 2000,
        pow_nonce: 0,
        controller_keys: vec![ControllerKey {
            id: format!("{}#primary", victim_did),
            key_type: "Ed25519".to_string(),
            public_key: attacker_pub_b64, // Attacker inserts their own public key!
        }],
        manifest: None,
        revocation_keys: vec![],
        signature: None,
    };
    forged_doc.mine_pow();

    let signed_forgery = forged_doc.sign(&attacker_key).unwrap();

    // THIS MUST FAIL, because verify() now checks that the
    // signature matches the key belonging to the DID!
    assert!(
        signed_forgery.verify().is_err(),
        "Fix confirmed: Attacker cannot statelessly hijack the DID"
    );
}
