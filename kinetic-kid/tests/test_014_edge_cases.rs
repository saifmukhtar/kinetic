use base64::{engine::general_purpose::URL_SAFE_NO_PAD as b64_url, Engine};
use ed25519_dalek::SigningKey;
use kinetic_kid::{CapabilityManifest, ControllerKey, KidDocument, KidError, KineticDid};
use rand_core::OsRng;

fn generate_keypair() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

fn create_valid_doc_and_key() -> (KidDocument, SigningKey) {
    let keypair = generate_keypair();
    let pub_key_b64 = b64_url.encode(keypair.verifying_key().to_bytes());

    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(keypair.verifying_key().to_bytes());
    let hash = hasher.finalize();
    let mut hex_hash = String::new();
    for byte in hash {
        use std::fmt::Write;
        let _ = write!(&mut hex_hash, "{:02x}", byte);
    }

    let did = KineticDid::new(&format!("did:kin:{}", hex_hash)).unwrap();
    let mut doc = KidDocument {
        doc_type: "kinetic.kid.v1".to_string(),
        kid: did.clone(),
        created_at: 1000,
        pow_nonce: 0,
        controller_keys: vec![ControllerKey {
            id: format!("{}#primary", did),
            key_type: "Ed25519".to_string(),
            public_key: pub_key_b64,
        }],
        manifest: None,
        revocation_keys: vec![],
        signature: None,
    };
    doc.mine_pow();
    (doc, keypair)
}

#[test]
fn test_kid_error_did_prefix() {
    assert!(matches!(
        KineticDid::new("did:web:123"),
        Err(KidError::InvalidDidPrefix)
    ));
}

#[test]
fn test_kid_error_did_empty() {
    assert!(matches!(
        KineticDid::new("did:kin:"),
        Err(KidError::InvalidDidFormat)
    ));
}

#[test]
fn test_doc_verify_missing_signature() {
    let (doc, _) = create_valid_doc_and_key();
    assert!(matches!(doc.verify(), Err(KidError::MissingSignature)));
}

#[test]
fn test_doc_verify_invalid_signature_length() {
    let (mut doc, _) = create_valid_doc_and_key();
    doc.signature = Some(b64_url.encode(b"short"));
    assert!(matches!(doc.verify(), Err(KidError::InvalidSignature)));
}

#[test]
fn test_doc_verify_invalid_signature_bytes() {
    let (mut doc, _) = create_valid_doc_and_key();
    let bad_sig = [0u8; 64]; // Zeroes
    doc.signature = Some(b64_url.encode(bad_sig));
    assert!(matches!(doc.verify(), Err(KidError::InvalidSignature)));
}

#[test]
fn test_doc_verify_invalid_pow() {
    let (mut doc, key) = create_valid_doc_and_key();
    doc.pow_nonce = doc.pow_nonce.wrapping_add(1); // Break POW
    let signed = doc.sign(&key).unwrap();
    assert!(matches!(
        signed.verify(),
        Err(KidError::CanonicalizationError(_))
    ));
}

#[test]
fn test_doc_verify_no_controller_keys() {
    let (mut doc, key) = create_valid_doc_and_key();
    doc.controller_keys.clear();
    doc.mine_pow();
    let signed = doc.sign(&key).unwrap();
    // Verify will fail to find a matching key
    assert!(matches!(signed.verify(), Err(KidError::InvalidSignature)));
}

#[test]
fn test_doc_verify_unknown_key_type() {
    let (mut doc, key) = create_valid_doc_and_key();
    doc.controller_keys[0].key_type = "RSA".to_string();
    doc.mine_pow();
    let signed = doc.sign(&key).unwrap();
    assert!(matches!(signed.verify(), Err(KidError::InvalidSignature)));
}

#[test]
fn test_manifest_verify_kid_mismatch() {
    let (doc, _) = create_valid_doc_and_key();
    let mut other_doc = doc.clone();
    other_doc.kid = KineticDid::new("did:kin:other123").unwrap();

    let manifest = CapabilityManifest {
        doc_type: "kinetic.manifest.v1".to_string(),
        kid: other_doc.kid.clone(),
        version: 1,
        valid_from: 1000,
        pow_nonce: 0,
        services: vec![],
        signature: None,
    };
    assert!(matches!(
        manifest.verify(&doc),
        Err(KidError::UnauthorizedManifestSignature)
    ));
}

#[test]
fn test_manifest_verify_missing_signature() {
    let (doc, key) = create_valid_doc_and_key();
    let signed_doc = doc.clone().sign(&key).unwrap();
    let manifest = CapabilityManifest {
        doc_type: "kinetic.manifest.v1".to_string(),
        kid: doc.kid.clone(),
        version: 1,
        valid_from: 1000,
        pow_nonce: 0,
        services: vec![],
        signature: None,
    };
    assert!(matches!(
        manifest.verify(&signed_doc),
        Err(KidError::MissingSignature)
    ));
}

#[test]
fn test_manifest_verify_invalid_pow() {
    let (doc, key) = create_valid_doc_and_key();
    let signed_doc = doc.clone().sign(&key).unwrap();
    let mut manifest = CapabilityManifest {
        doc_type: "kinetic.manifest.v1".to_string(),
        kid: doc.kid.clone(),
        version: 1,
        valid_from: 1000,
        pow_nonce: 0,
        services: vec![],
        signature: None,
    };
    manifest.mine_pow();
    manifest.pow_nonce = manifest.pow_nonce.wrapping_add(1); // Break POW
    let signed_manifest = manifest.sign(&key).unwrap();
    assert!(matches!(
        signed_manifest.verify(&signed_doc),
        Err(KidError::CanonicalizationError(_))
    ));
}

#[test]
fn test_manifest_verify_invalid_signature() {
    let (doc, key) = create_valid_doc_and_key();
    let signed_doc = doc.clone().sign(&key).unwrap();
    let mut manifest = CapabilityManifest {
        doc_type: "kinetic.manifest.v1".to_string(),
        kid: doc.kid.clone(),
        version: 1,
        valid_from: 1000,
        pow_nonce: 0,
        services: vec![],
        signature: None,
    };
    manifest.mine_pow();
    let mut signed_manifest = manifest.sign(&key).unwrap();
    signed_manifest.signature = Some(b64_url.encode([0u8; 64])); // Invalid signature bytes
    assert!(matches!(
        signed_manifest.verify(&signed_doc),
        Err(KidError::UnauthorizedManifestSignature)
    ));
}

#[test]
fn test_manifest_verify_short_signature() {
    let (doc, key) = create_valid_doc_and_key();
    let signed_doc = doc.clone().sign(&key).unwrap();
    let mut manifest = CapabilityManifest {
        doc_type: "kinetic.manifest.v1".to_string(),
        kid: doc.kid.clone(),
        version: 1,
        valid_from: 1000,
        pow_nonce: 0,
        services: vec![],
        signature: None,
    };
    manifest.mine_pow();
    let mut signed_manifest = manifest.sign(&key).unwrap();
    signed_manifest.signature = Some(b64_url.encode(b"short")); // Short signature
    assert!(matches!(
        signed_manifest.verify(&signed_doc),
        Err(KidError::InvalidSignature)
    ));
}

#[test]
fn test_manifest_verify_no_matching_key() {
    let (doc, key) = create_valid_doc_and_key();
    let signed_doc = doc.clone().sign(&key).unwrap();

    let (_, other_key) = create_valid_doc_and_key();

    let mut manifest = CapabilityManifest {
        doc_type: "kinetic.manifest.v1".to_string(),
        kid: doc.kid.clone(),
        version: 1,
        valid_from: 1000,
        pow_nonce: 0,
        services: vec![],
        signature: None,
    };
    manifest.mine_pow();
    let signed_manifest = manifest.sign(&other_key).unwrap(); // Signed with wrong key
    assert!(matches!(
        signed_manifest.verify(&signed_doc),
        Err(KidError::UnauthorizedManifestSignature)
    ));
}

#[test]
fn test_validate_pow_edge_cases() {
    let zeros = [0u8; 32];
    // 0 target bits always passes
    assert!(kinetic_kid::validate_pow(&zeros, 0));
    // Zeros passes even max target
    assert!(kinetic_kid::validate_pow(&zeros, 255));
    // Fails if first bit is 1 and target is 1
    let mut bad_first_bit = [0u8; 32];
    bad_first_bit[0] = 0b1000_0000;
    assert!(!kinetic_kid::validate_pow(&bad_first_bit, 1));
}
