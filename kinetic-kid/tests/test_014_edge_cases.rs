use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as b64_url};
use kinetic_kid::{Manifest, ControllerKey, Document, Error, Did};
use kinetic_primitives::keys::KineticKeypair;

fn generate_keypair() -> KineticKeypair {
    KineticKeypair::generate()
}

fn create_valid_doc_and_key() -> (Document, KineticKeypair) {
    let keypair = generate_keypair();
    let pub_key_b64 = b64_url.encode(&keypair.pubkey_bytes());

    let hash = kinetic_primitives::sha256_hash(&keypair.pubkey_bytes());
    let mut hex_hash = String::new();
    for byte in hash {
        use std::fmt::Write;
        let _ = write!(&mut hex_hash, "{:02x}", byte);
    }

    let did = Did::new(&format!("did:kin:{}", hex_hash)).unwrap();
    let doc = Document {
        doc_type: "kinetic.kid.v1".to_string(),
        kid: did.clone(),
        created_at: 1000,
        controller_keys: vec![ControllerKey {
            id: format!("{}#primary", did),
            key_type: "ML-DSA-65".to_string(),
            public_key: pub_key_b64,
        }],
        manifest: None,
        revocation_keys: vec![],
        deactivated: false,
        signature: None,
    };
    (doc, keypair)
}

#[test]
fn test_kid_error_did_prefix() {
    assert!(matches!(
        Did::new("did:web:123"),
        Err(Error::InvalidDidPrefix)
    ));
}

#[test]
fn test_kid_error_did_empty() {
    assert!(matches!(
        Did::new("did:kin:"),
        Err(Error::InvalidDidHexLength)
    ));
}

#[test]
fn test_doc_verify_missing_signature() {
    let (doc, _) = create_valid_doc_and_key();
    assert!(matches!(doc.verify(), Err(Error::MissingSignature)));
}

#[test]
fn test_doc_verify_invalid_signature_length() {
    let (mut doc, _) = create_valid_doc_and_key();
    doc.signature = Some(b64_url.encode(b"short"));
    assert!(matches!(doc.verify(), Err(Error::InvalidSignature)));
}

#[test]
fn test_doc_verify_invalid_signature_bytes() {
    let (mut doc, _) = create_valid_doc_and_key();
    let bad_sig = [0u8; 64]; // Zeroes
    doc.signature = Some(b64_url.encode(bad_sig));
    assert!(matches!(doc.verify(), Err(Error::InvalidSignature)));
}

#[test]
fn test_doc_verify_no_controller_keys() {
    let (mut doc, key) = create_valid_doc_and_key();
    doc.controller_keys.clear();
    let signed = doc.sign(&key).unwrap();
    // Verify will fail to find a matching key
    assert!(matches!(signed.verify(), Err(Error::InvalidSignature)));
}

#[test]
fn test_doc_verify_unknown_key_type() {
    let (mut doc, key) = create_valid_doc_and_key();
    doc.controller_keys[0].key_type = "RSA".to_string();
    let signed = doc.sign(&key).unwrap();
    assert!(matches!(signed.verify(), Err(Error::InvalidSignature)));
}

#[test]
fn test_manifest_verify_kid_mismatch() {
    let (doc, _) = create_valid_doc_and_key();
    let mut other_doc = doc.clone();
    other_doc.kid = Did::new(&format!("did:kin:{}", "c".repeat(64))).unwrap();

    let manifest = Manifest {
        doc_type: "kinetic.manifest.v1".to_string(),
        kid: other_doc.kid.clone(),
        version: 1,
        valid_from: 1000,
        expires_at: None,
        services: vec![],
        signature: None,
    };
    assert!(matches!(
        manifest.verify_local(&doc),
        Err(Error::UnauthorizedManifestSignature)
    ));
}

#[test]
fn test_manifest_verify_missing_signature() {
    let (doc, key) = create_valid_doc_and_key();
    let signed_doc = doc.clone().sign(&key).unwrap();
    let manifest = Manifest {
        doc_type: "kinetic.manifest.v1".to_string(),
        kid: doc.kid.clone(),
        version: 1,
        valid_from: 1000,
        expires_at: None,
        services: vec![],
        signature: None,
    };
    assert!(matches!(
        manifest.verify_local(&signed_doc),
        Err(Error::MissingSignature)
    ));
}

#[test]
fn test_manifest_verify_invalid_signature() {
    let (doc, key) = create_valid_doc_and_key();
    let signed_doc = doc.clone().sign(&key).unwrap();
    let manifest = Manifest {
        doc_type: "kinetic.manifest.v1".to_string(),
        kid: doc.kid.clone(),
        version: 1,
        valid_from: 1000,
        expires_at: None,
        services: vec![],
        signature: None,
    };
    let mut signed_manifest = manifest.sign(&key).unwrap();
    signed_manifest.signature = Some(b64_url.encode([0u8; 3309])); // Invalid signature bytes
    assert!(matches!(
        signed_manifest.verify_local(&signed_doc),
        Err(Error::UnauthorizedManifestSignature)
    ));
}

#[test]
fn test_manifest_verify_short_signature() {
    let (doc, key) = create_valid_doc_and_key();
    let signed_doc = doc.clone().sign(&key).unwrap();
    let manifest = Manifest {
        doc_type: "kinetic.manifest.v1".to_string(),
        kid: doc.kid.clone(),
        version: 1,
        valid_from: 1000,
        expires_at: None,
        services: vec![],
        signature: None,
    };
    let mut signed_manifest = manifest.sign(&key).unwrap();
    signed_manifest.signature = Some(b64_url.encode(b"short")); // Short signature
    assert!(matches!(
        signed_manifest.verify_local(&signed_doc),
        Err(Error::UnauthorizedManifestSignature)
    ));
}

#[test]
fn test_manifest_verify_no_matching_key() {
    let (doc, key) = create_valid_doc_and_key();
    let signed_doc = doc.clone().sign(&key).unwrap();

    let (_, other_key) = create_valid_doc_and_key();

    let manifest = Manifest {
        doc_type: "kinetic.manifest.v1".to_string(),
        kid: doc.kid.clone(),
        version: 1,
        valid_from: 1000,
        expires_at: None,
        services: vec![],
        signature: None,
    };
    let signed_manifest = manifest.sign(&other_key).unwrap(); // Signed with wrong key
    assert!(matches!(
        signed_manifest.verify_local(&signed_doc),
        Err(Error::UnauthorizedManifestSignature)
    ));
}
