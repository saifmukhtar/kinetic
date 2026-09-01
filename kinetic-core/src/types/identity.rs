//! Cryptographic identity, Kinetic Identity Document (KID) documents, and post-quantum key management.
//!
//! This module handles ML-DSA-65 post-quantum signing keypairs, PBKDF2-HMAC-SHA512 key derivation
//! (600,000 iterations), atomic file writes with strict POSIX `0o600` permissions, and memory zeroization.
//!
//! ## Key File Format
//!
//! The identity file stores exactly **32 bytes** — the raw ML-DSA-65 seed (not the full
//! expanded signing key). On load, the 32-byte seed is passed to `SigningKey::from_seed()`
//! to reconstruct the full keypair deterministically. This means the identity file is
//! fully reproducible from a BIP-39 mnemonic via `save_keypair_from_mnemonic`.
//!
//! All `signable_bytes()` methods produce a network-scoped byte string:
//! `[network_salt][u32_be(name.len())][name_bytes][u32_be(payload.len())][payload_bytes]`
//!
//! The 32-byte `NETWORK_SALT` prefix prevents cross-network replay attacks, as it
//! cryptographically binds the signatures to the specific NETWORK_ID and Governance Root Key.

pub use kinetic_types::identity::{AuthorizedKid, AuthorizedManifest};

/// Loads an ML-DSA-65 post-quantum signing keypair from disk.
///
/// Reads the 32-byte seed from the identity file at `KINETIC_KEY_PATH` or
/// `{base_dir}/{filename}` and reconstructs the full ML-DSA-65 signing key
/// deterministically via `SigningKey::from_seed()`.
///
/// # Returns
///
/// The reconstructed [`ml_dsa::SigningKey<ml_dsa::MlDsa65>`] on success.
///
/// # Errors
///
/// - Returns [`crate::error::IdentityError::IdentityNotFound`] (`KIN-IDN-003`) if the key file does not exist.
/// - Returns [`crate::error::IdentityError::CorruptedIdentityFile`] (`KIN-IDN-002`) if the file is not exactly 32 bytes.
/// - Returns [`crate::error::IdentityError::Io`] (`KIN-IDN-001`) if a filesystem read error occurs.
#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    use tempfile::tempdir;

    #[test]
    fn test_signable_bytes_kid() {
        let valid_did = format!(
            "{}0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            crate::constants::DID_PREFIX
        );
        let kid = kinetic_kid::did::Did::new(&valid_did).unwrap();
        let doc = kinetic_kid::document::Document {
            doc_type: "kinetic.kid.v1".to_string(),
            kid,
            created_at: 0,
            controller_keys: vec![],
            manifest: None,
            revocation_keys: vec![],
            signature: None,
            deactivated: false,
        };
        let auth_kid = AuthorizedKid {
            name: "test.kin".to_string(),
            kid_doc: doc,
            owner_signature: vec![1, 2, 3],
        };

        let bytes = auth_kid.signable_bytes(crate::constants::NETWORK_SALT);
        let mut prefix = Vec::new();
        prefix.extend_from_slice(crate::constants::NETWORK_SALT);
        prefix.extend_from_slice(b"-auth-kid-v1");
        assert!(bytes.starts_with(&prefix));
        assert!(bytes.windows(8).any(|w| w == b"test.kin"));
    }

    #[test]
    fn test_signable_bytes_manifest() {
        let valid_did = "did:kin:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let kid = kinetic_kid::did::Did::new(valid_did).unwrap();
        let manifest = kinetic_kid::manifest::Manifest {
            doc_type: "kinetic.manifest.v1".to_string(),
            kid,
            version: 1,
            valid_from: 0,
            expires_at: None,
            services: vec![],
            signature: None,
        };
        let auth_manifest = AuthorizedManifest {
            name: "test.kin".to_string(),
            manifest,
            kid_doc: None,
            owner_signature: vec![1, 2, 3],
        };

        let bytes = auth_manifest.signable_bytes(crate::constants::NETWORK_SALT);
        let mut prefix = Vec::new();
        prefix.extend_from_slice(crate::constants::NETWORK_SALT);
        prefix.extend_from_slice(b"-auth-manifest-v1");
        assert!(bytes.starts_with(&prefix));
        assert!(bytes.windows(8).any(|w| w == b"test.kin"));
    }
}
