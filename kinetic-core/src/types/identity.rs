//! Cryptographic identity, Key Identifier (KID) documents, and post-quantum key management.
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
//! ## Signable Byte Format
//!
//! All `signable_bytes()` methods produce a network-scoped byte string:
//! `[network_id_prefix][u32_be(name.len())][name_bytes][u32_be(payload.len())][payload_bytes]`
//!
//! The `KINETIC_NETWORK_ID` prefix prevents cross-network replay attacks.

use serde::{Deserialize, Serialize};

/// Authorized Key Identifier (KID) document bound to a `.kin` domain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizedKid {
    /// Domain name associated with this KID.
    pub name: String,
    /// Embedded KID document containing public keys and controller data.
    pub kid_doc: kinetic_kid::document::KidDocument,
    /// Domain owner's signature verifying the KID attachment.
    pub owner_signature: Vec<u8>,
}

impl AuthorizedKid {
    /// Serializes this KID authorization into a canonical byte string for owner signature verification.
    ///
    /// The byte layout is:
    /// `{NETWORK_ID}-auth-kid-v1` + `u32_be(name.len())` + `name_bytes` + `u32_be(canon_json.len())` + `canon_json_bytes`
    ///
    /// The `{NETWORK_ID}` prefix prevents a signature produced on one Kinetic network (e.g. `.kin`)
    /// from being replayed on another (e.g. `.corp`).
    ///
    /// # Returns
    ///
    /// A `Vec<u8>` containing the fully serialized, network-scoped signable payload.
    pub fn signable_bytes(&self) -> Vec<u8> {
        let prefix = concat!(env!("KINETIC_NETWORK_ID"), "-auth-kid-v1").as_bytes();
        let canon_bytes = self.kid_doc.canonicalize().unwrap_or_default();
        let canon_bytes = canon_bytes.as_bytes();
        let mut bytes =
            Vec::with_capacity(prefix.len() + 4 + self.name.len() + 4 + canon_bytes.len());
        bytes.extend_from_slice(prefix);
        bytes.extend_from_slice(&(self.name.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.name.as_bytes());
        bytes.extend_from_slice(&(canon_bytes.len() as u32).to_be_bytes());
        bytes.extend_from_slice(canon_bytes);
        bytes
    }
}

/// Authorized capability manifest bound to a `.kin` domain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizedManifest {
    /// Domain name associated with this capability manifest.
    pub name: String,
    /// Embedded capability manifest structure.
    pub manifest: kinetic_kid::manifest::CapabilityManifest,
    /// Optional associated KID document.
    pub kid_doc: Option<kinetic_kid::document::KidDocument>,
    /// Domain owner's signature verifying the manifest attachment.
    pub owner_signature: Vec<u8>,
}

impl AuthorizedManifest {
    /// Serializes this manifest authorization into a canonical byte string for owner signature verification.
    ///
    /// The byte layout is:
    /// `{NETWORK_ID}-auth-manifest-v1` + `u32_be(name.len())` + `name_bytes` + `u32_be(canon_json.len())` + `canon_json_bytes`
    ///
    /// # Returns
    ///
    /// A `Vec<u8>` containing the fully serialized, network-scoped signable payload.
    pub fn signable_bytes(&self) -> Vec<u8> {
        let prefix = concat!(env!("KINETIC_NETWORK_ID"), "-auth-manifest-v1").as_bytes();
        let canon_bytes = self.manifest.canonicalize().unwrap_or_default();
        let canon_bytes = canon_bytes.as_bytes();
        let mut bytes =
            Vec::with_capacity(prefix.len() + 4 + self.name.len() + 4 + canon_bytes.len());
        bytes.extend_from_slice(prefix);
        bytes.extend_from_slice(&(self.name.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.name.as_bytes());
        bytes.extend_from_slice(&(canon_bytes.len() as u32).to_be_bytes());
        bytes.extend_from_slice(canon_bytes);
        bytes
    }
}

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
#[cfg(not(target_arch = "wasm32"))]
pub fn load_keypair(
    filename: &str,
) -> Result<ml_dsa::SigningKey<ml_dsa::MlDsa65>, crate::error::IdentityError> {
    use std::fs;
    use std::path::PathBuf;

    let key_path = std::env::var(crate::constants::ENV_KINETIC_KEY_PATH)
        .map(PathBuf::from)
        .unwrap_or_else(|_| crate::config::get_base_dir().join(filename));

    if key_path.exists() {
        let bytes = fs::read(&key_path)?;
        if bytes.len() == 32 {
            let mut array = [0u8; 32];
            array.copy_from_slice(&bytes);
            return Ok(ml_dsa::SigningKey::<ml_dsa::MlDsa65>::from_seed(
                (&array).into(),
            ));
        } else {
            return Err(crate::error::IdentityError::CorruptedIdentityFile(
                format!("Expected 32 bytes, found {}. Please restore from a backup or manually delete the file to generate a new identity.", bytes.len())
            ));
        }
    }

    Err(crate::error::IdentityError::IdentityNotFound("Identity file not found. Please run 'kinetic seed init' or use the Desktop app to create one.".to_string()))
}

/// Loads an ML-DSA-65 post-quantum signing keypair from an AES-256-GCM encrypted file on disk.
#[cfg(not(target_arch = "wasm32"))]
pub fn load_encrypted_keypair(
    path: &std::path::Path,
    password: &str,
) -> Result<ml_dsa::SigningKey<ml_dsa::MlDsa65>, crate::error::IdentityError> {
    use aes_gcm::{
        aead::{Aead, KeyInit},
        Aes256Gcm, Nonce,
    };
    use pbkdf2::pbkdf2_hmac;
    use sha2::Sha256;
    use std::fs;

    if path.exists() {
        let bytes = fs::read(path)?;
        if bytes.len() < 16 + 12 + 16 {
            // salt + nonce + mac
            return Err(crate::error::IdentityError::CorruptedIdentityFile(
                "Encrypted file too short".into(),
            ));
        }

        let salt = &bytes[0..16];
        let nonce_bytes = &bytes[16..28];
        let ciphertext = &bytes[28..];

        let mut key = [0u8; 32];
        pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, 600_000, &mut key);

        let cipher = Aes256Gcm::new((&key).into());
        let nonce = Nonce::from_slice(nonce_bytes);

        let decrypted = cipher.decrypt(nonce, ciphertext).map_err(|_| {
            crate::error::IdentityError::DecryptionFailed(
                "Incorrect password or corrupted file".into(),
            )
        })?;

        if decrypted.len() == 32 {
            let mut array = [0u8; 32];
            array.copy_from_slice(&decrypted);
            return Ok(ml_dsa::SigningKey::<ml_dsa::MlDsa65>::from_seed(
                (&array).into(),
            ));
        } else {
            return Err(crate::error::IdentityError::CorruptedIdentityFile(format!(
                "Expected 32 bytes from decryption, found {}.",
                decrypted.len()
            )));
        }
    }

    Err(crate::error::IdentityError::IdentityNotFound(format!(
        "Encrypted identity file not found at {:?}",
        path
    )))
}

/// Derives an ML-DSA-65 signing keypair from a BIP-39 mnemonic and saves the 32-byte seed to disk.
///
/// Key derivation steps:
/// 1. Parse the 24-word English BIP-39 mnemonic.
/// 2. Convert to the BIP-39 raw entropy seed (64 bytes, no passphrase).
/// 3. Compute `salt = SHA-256(seed)`.
/// 4. Derive a 32-byte key via PBKDF2-HMAC-SHA512 (600,000 iterations, NIST SP 800-132).
/// 5. Write the 32-byte derived seed atomically to `{base_dir}/{filename}` with `0o600` permissions.
/// 6. Zeroize all intermediate buffers before returning.
///
/// # Returns
///
/// The derived [`ml_dsa::SigningKey<ml_dsa::MlDsa65>`] on success.
///
/// # Errors
///
/// - Returns [`crate::error::IdentityError::InvalidSeedPhrase`] (`KIN-IDN-004`) if the mnemonic fails BIP-39 parsing.
/// - Returns [`crate::error::IdentityError::Io`] (`KIN-IDN-001`) if directory creation or atomic file write fails.
#[cfg(not(target_arch = "wasm32"))]
pub fn save_keypair_from_mnemonic(
    filename: &str,
    phrase: &str,
) -> Result<ml_dsa::SigningKey<ml_dsa::MlDsa65>, crate::error::IdentityError> {
    use bip39::{Language, Mnemonic};
    use pbkdf2::pbkdf2_hmac;
    use sha2::{Digest, Sha256, Sha512};
    use std::fs::{self, OpenOptions};
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    use std::path::PathBuf;
    use zeroize::Zeroize;

    let mnemonic = Mnemonic::parse_in(Language::English, phrase)
        .map_err(|e| crate::error::IdentityError::InvalidSeedPhrase(format!("{}", e)))?;

    let mut seed = mnemonic.to_seed("");

    // Use the SHA-256 hash of the seed itself as a dynamic salt
    let salt = Sha256::digest(seed);

    let mut derived = [0u8; 32];
    pbkdf2_hmac::<Sha512>(&seed, &salt, 600_000, &mut derived);

    let signing_key = ml_dsa::SigningKey::<ml_dsa::MlDsa65>::from_seed((&derived).into());

    // Securely wipe intermediate seed and derived buffers
    seed.zeroize();
    derived.zeroize();

    let key_path = std::env::var(crate::constants::ENV_KINETIC_KEY_PATH)
        .map(PathBuf::from)
        .unwrap_or_else(|_| crate::config::get_base_dir().join(filename));

    if let Some(parent) = key_path.parent() {
        let _ = fs::create_dir_all(parent);
    }

    let tmp_path = key_path.with_extension("tmp");
    let _ = fs::remove_file(&tmp_path);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp_path)?;
    use ml_dsa::KeyExport;
    file.write_all(&signing_key.to_bytes())?;
    file.sync_all()?;

    fs::rename(tmp_path, &key_path)?;

    Ok(signing_key)
}

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
        let kid = kinetic_kid::did::KineticDid::new(&valid_did).unwrap();
        let doc = kinetic_kid::document::KidDocument {
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

        let bytes = auth_kid.signable_bytes();
        let prefix = concat!(env!("KINETIC_NETWORK_ID"), "-auth-kid-v1").as_bytes();
        assert!(bytes.starts_with(prefix));
        assert!(bytes.windows(8).any(|w| w == b"test.kin"));
    }

    #[test]
    fn test_signable_bytes_manifest() {
        let valid_did = "did:kin:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let kid = kinetic_kid::did::KineticDid::new(valid_did).unwrap();
        let manifest = kinetic_kid::manifest::CapabilityManifest {
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

        let bytes = auth_manifest.signable_bytes();
        let prefix = concat!(env!("KINETIC_NETWORK_ID"), "-auth-manifest-v1").as_bytes();
        assert!(bytes.starts_with(prefix));
        assert!(bytes.windows(8).any(|w| w == b"test.kin"));
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn test_identity_key_lifecycle() {
        // Run all key lifecycle tests synchronously in one function
        // to avoid race conditions with KINETIC_KEY_PATH env var
        let dir = tempdir().unwrap();

        // 1. Not Found
        std::env::set_var(
            crate::constants::ENV_KINETIC_KEY_PATH,
            dir.path().join("missing.bin"),
        );
        let result = load_keypair("test.bin");
        assert!(matches!(
            result,
            Err(crate::error::IdentityError::IdentityNotFound(_))
        ));

        // 2. Corrupted File
        let corrupt_path = dir.path().join("corrupted.bin");
        fs::write(&corrupt_path, b"too_short").unwrap();
        std::env::set_var(crate::constants::ENV_KINETIC_KEY_PATH, &corrupt_path);
        let result = load_keypair("test.bin");
        assert!(matches!(
            result,
            Err(crate::error::IdentityError::CorruptedIdentityFile(_))
        ));

        // 3. Invalid Seed Phrase
        let result = save_keypair_from_mnemonic("test.bin", "not a valid seed phrase");
        assert!(matches!(
            result,
            Err(crate::error::IdentityError::InvalidSeedPhrase(_))
        ));

        // 4. Successful Save and Load
        let valid_path = dir.path().join("valid_key.bin");
        std::env::set_var(crate::constants::ENV_KINETIC_KEY_PATH, &valid_path);
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let saved_key = save_keypair_from_mnemonic("test.bin", phrase).unwrap();
        let loaded_key = load_keypair("test.bin").unwrap();
        use ml_dsa::KeyExport;
        assert_eq!(saved_key.to_bytes(), loaded_key.to_bytes());

        // 5. Encrypted Keypair logic (manual encryption simulation)
        let encrypted_path = dir.path().join("encrypted.aes");
        use aes_gcm::{
            aead::{Aead, KeyInit},
            Aes256Gcm, Nonce,
        };
        use pbkdf2::pbkdf2_hmac;
        use sha2::Sha256;
        use std::fs::File;
        use std::io::Read;

        let mut salt = [0u8; 16];
        let mut nonce_bytes = [0u8; 12];
        let mut urandom = File::open("/dev/urandom").expect("Failed to open /dev/urandom");
        urandom.read_exact(&mut salt).expect("RNG failure");
        urandom.read_exact(&mut nonce_bytes).expect("RNG failure");

        let mut derived_key = [0u8; 32];
        pbkdf2_hmac::<Sha256>(b"strong_password", &salt, 600_000, &mut derived_key);

        let cipher = Aes256Gcm::new((&derived_key).into());
        let nonce = Nonce::from_slice(&nonce_bytes);
        let raw_seed = [5u8; 32]; // dummy seed

        let ciphertext = cipher.encrypt(nonce, raw_seed.as_ref()).unwrap();

        let mut final_payload = Vec::new();
        final_payload.extend_from_slice(&salt);
        final_payload.extend_from_slice(&nonce_bytes);
        final_payload.extend_from_slice(&ciphertext);

        fs::write(&encrypted_path, final_payload).unwrap();

        let loaded_encrypted = load_encrypted_keypair(&encrypted_path, "strong_password").unwrap();
        assert_eq!(
            loaded_encrypted.to_bytes(),
            ml_dsa::SigningKey::<ml_dsa::MlDsa65>::from_seed((&raw_seed).into()).to_bytes()
        );

        let bad_pass = load_encrypted_keypair(&encrypted_path, "wrong_password");
        assert!(matches!(
            bad_pass,
            Err(crate::error::IdentityError::DecryptionFailed(_))
        ));

        // Clean up env var
        std::env::remove_var(crate::constants::ENV_KINETIC_KEY_PATH);
    }
}
