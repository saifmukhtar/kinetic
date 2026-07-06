//! # kinetic-kid
//!
//! Kinetic Identity Documents (KIDs) — the self-sovereign identity layer.
//!
//! A KID is a decentralised identifier (DID) anchored to the Kinetic `.kin`
//! naming network. This crate defines how identities are created, signed,
//! verified, and extended with capability manifests.
//!
//! ## Core concepts
//!
//! - **[`KineticDid`]** — A validated `did:kin:<hex>` string. The hex suffix
//!   is the SHA-256 hash of the controller's primary public key.
//! - **[`KidDocument`]** — The identity document that binds a DID to one or
//!   more [`ControllerKey`]s. It is signed with Ed25519 and stamped with a
//!   Proof-of-Work nonce (target: [`KID_POW_TARGET`] leading zero bits) to
//!   rate-limit identity creation on-chain.
//! - **[`CapabilityManifest`]** — An optional extension signed by the
//!   controller that lists services (websites, APIs, etc.) associated with
//!   the identity.
//!
//! ## Serialisation
//!
//! All documents are canonicalised using **JCS** (JSON Canonicalisation Scheme,
//! RFC 8785) before signing so that the byte representation is deterministic
//! across platforms.

#![deny(missing_docs)]

/// DID parsing and validation for the `did:kin:` scheme.
pub mod did;
/// KID document types: [`KidDocument`], [`ControllerKey`], and [`ManifestPointer`].
pub mod document;
/// [`KidError`]: the unified error type for kinetic-kid operations.
pub mod error;
/// Capability manifest types: [`CapabilityManifest`] and [`ServiceEntry`].
pub mod manifest;

pub use did::KineticDid;
pub use document::{ControllerKey, KidDocument, ManifestPointer};
pub use error::KidError;
pub use manifest::{CapabilityManifest, ServiceEntry};

/// The required number of leading zero bits in the SHA-256 PoW hash for a
/// valid [`KidDocument`] or [`CapabilityManifest`].
pub const KID_POW_TARGET: u32 = 20;

/// Returns `true` if the given SHA-256 `hash` satisfies `target_bits` leading
/// zero bits, which is the Proof-of-Work requirement for KID documents.
pub fn validate_pow(hash: &[u8; 32], target_bits: u32) -> bool {
    let target_bytes = (target_bits / 8) as usize;
    let remainder_bits = target_bits % 8;

    for &byte in hash.iter().take(target_bytes) {
        if byte != 0 {
            return false;
        }
    }

    if remainder_bits > 0 {
        let mask = 0xFF << (8 - remainder_bits);
        if (hash[target_bytes] & mask) != 0 {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD as b64_url, Engine};
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;

    fn generate_keypair() -> SigningKey {
        let mut csprng = OsRng;
        SigningKey::generate(&mut csprng)
    }

    #[test]
    fn test_did_parsing() {
        assert!(KineticDid::new("did:kin:12345").is_ok());
        assert!(KineticDid::new("did:example:12345").is_err());
        assert!(KineticDid::new("did:kin:").is_err());
    }

    #[test]
    fn test_jcs_canonicalization() {
        let did = KineticDid::new("did:kin:test").unwrap();

        let doc = KidDocument {
            doc_type: "kinetic.kid.v1".to_string(),
            kid: did.clone(),
            created_at: 1000,
            pow_nonce: 0,
            controller_keys: vec![],
            manifest: None,
            revocation_keys: vec![],
            signature: None,
        };

        let jcs_str = doc.canonicalize().unwrap();
        // Optional fields are stripped when None
        assert!(!jcs_str.contains("manifest"));
        assert!(!jcs_str.contains("signature"));

        // Fields must be in lexicographical order per JCS
        let expected = r#"{"controller_keys":[],"created_at":1000,"kid":"did:kin:test","pow_nonce":0,"type":"kinetic.kid.v1"}"#;
        assert_eq!(jcs_str, expected);
    }

    #[test]
    fn test_document_signing_and_verification() {
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
            created_at: 1234567890,
            pow_nonce: 0,
            controller_keys: vec![ControllerKey {
                id: format!("did:kin:{}#primary", hex_hash),
                key_type: "Ed25519".to_string(),
                public_key: pub_key_b64,
            }],
            manifest: None,
            revocation_keys: vec![],
            signature: None,
        };

        doc.mine_pow();
        let signed_doc = doc.sign(&keypair).unwrap();
        assert!(signed_doc.signature.is_some());

        assert!(signed_doc.verify().is_ok());

        // Tampering with any field must invalidate the signature
        let mut corrupted_doc = signed_doc.clone();
        corrupted_doc.created_at = 9999999999;
        assert!(corrupted_doc.verify().is_err());
    }

    #[test]
    fn test_manifest_verification() {
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
                id: format!("did:kin:{}#primary", hex_hash),
                key_type: "Ed25519".to_string(),
                public_key: pub_key_b64,
            }],
            manifest: None,
            revocation_keys: vec![],
            signature: None,
        };

        let mut manifest = CapabilityManifest {
            doc_type: "kinetic.manifest.v1".to_string(),
            kid: did,
            version: 1,
            valid_from: 1000,
            pow_nonce: 0,
            services: vec![ServiceEntry {
                id: "web".to_string(),
                service_type: "website".to_string(),
                protocol: "https".to_string(),
                endpoint: "https://example.com".to_string(),
            }],
            signature: None,
        };

        doc.mine_pow();
        manifest.mine_pow();
        let signed_manifest = manifest.sign(&keypair).unwrap();

        assert!(signed_manifest.verify(&doc).is_ok());

        // A manifest signed by a different key must be rejected
        let bad_keypair = generate_keypair();
        let bad_doc = KidDocument {
            doc_type: "kinetic.kid.v1".to_string(),
            kid: KineticDid::new("did:kin:test2").unwrap(),
            created_at: 1000,
            pow_nonce: 0,
            controller_keys: vec![ControllerKey {
                id: "did:kin:test2#bad".to_string(),
                key_type: "Ed25519".to_string(),
                public_key: b64_url.encode(bad_keypair.verifying_key().to_bytes()),
            }],
            manifest: None,
            revocation_keys: vec![],
            signature: None,
        };

        assert!(matches!(
            signed_manifest.verify(&bad_doc),
            Err(KidError::UnauthorizedManifestSignature)
        ));
    }
}
