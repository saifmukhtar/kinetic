use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as b64_url};
use kinetic_kid::{ControllerKey, Did, Document};
use kinetic_primitives::kinetic_keypair::ControllerPrivKey;

#[test]
fn test_013_kid_takeover() {
    // 1. Victim generates their identity
    let victim_key = ControllerPrivKey::generate();
    let victim_pub_b64 = b64_url.encode(victim_key.to_pubkey().as_bytes());
    let hash = kinetic_primitives::sha256_hash(victim_key.to_pubkey().as_bytes());
    let mut hex_hash = String::new();
    for byte in hash {
        use std::fmt::Write;
        write!(&mut hex_hash, "{:02x}", byte).unwrap();
    }
    let victim_did = format!("did:kin:{}", hex_hash);

    let doc = Document {
        doc_type: "kinetic.kid.v1".to_string(),
        kid: Did::new(&victim_did).unwrap(),
        created_at: kinetic_kyn::types::UTime(1000),
        controller_keys: vec![ControllerKey {
            id: format!("{}#primary", victim_did),
            key_type: "Controller".to_string(),
            public_key: victim_pub_b64,
        }],
        manifest: None,
        revocation_keys: vec![],
        deactivated: false,
        signature: None,
    };
    let victim_doc = doc.sign_with_controller(&victim_key).unwrap();
    assert!(victim_doc.verify().is_ok());

    // 2. Attacker generates a random key and attempts a DID takeover of the victim's DID
    let attacker_key = ControllerPrivKey::generate();
    let attacker_pub_b64 = b64_url.encode(attacker_key.to_pubkey().as_bytes());

    let forged_doc = Document {
        doc_type: "kinetic.kid.v1".to_string(),
        kid: Did::new(&victim_did).unwrap(), // Claiming victim's DID!
        created_at: kinetic_kyn::types::UTime(2000),
        controller_keys: vec![ControllerKey {
            id: format!("{}#primary", victim_did),
            key_type: "Controller".to_string(),
            public_key: attacker_pub_b64, // Attacker inserts their own public key!
        }],
        manifest: None,
        revocation_keys: vec![],
        deactivated: false,
        signature: None,
    };
    let signed_forgery = forged_doc.sign_with_controller(&attacker_key).unwrap();

    // The forged document fails `verify_genesis()` on first publication:
    // the attacker's public key does not hash to the victim's DID.
    // (The store calls verify_genesis() when no existing record is found.)
    assert!(
        signed_forgery.verify_genesis().is_err(),
        "Security: forged KID with attacker key must not pass genesis DID binding"
    );
}
