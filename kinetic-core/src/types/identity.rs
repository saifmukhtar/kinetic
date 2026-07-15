use serde::{Deserialize, Serialize};

/// Represents an authorized Key Identifier (KID) associated with a domain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizedKid {
    pub name: String,
    pub kid_doc: kinetic_kid::document::KidDocument,
    pub owner_signature: Vec<u8>,
}

impl AuthorizedKid {
    /// Serializes the KID document into a byte vector for cryptographic signing.
    pub fn signable_bytes(&self) -> Vec<u8> {
        let canon_bytes = self.kid_doc.canonicalize().unwrap_or_default();
        let canon_bytes = canon_bytes.as_bytes();
        let mut bytes = Vec::with_capacity(19 + 4 + self.name.len() + 4 + canon_bytes.len());
        bytes.extend_from_slice(b"kinetic-auth-kid-v1");
        bytes.extend_from_slice(&(self.name.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.name.as_bytes());
        bytes.extend_from_slice(&(canon_bytes.len() as u32).to_be_bytes());
        bytes.extend_from_slice(canon_bytes);
        bytes
    }
}

/// Represents an authorized capability manifest bound to a domain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizedManifest {
    pub name: String,
    pub manifest: kinetic_kid::manifest::CapabilityManifest,
    pub owner_signature: Vec<u8>,
}

impl AuthorizedManifest {
    /// Serializes the manifest into a byte vector for cryptographic signing.
    pub fn signable_bytes(&self) -> Vec<u8> {
        let canon_bytes = self.manifest.canonicalize().unwrap_or_default();
        let canon_bytes = canon_bytes.as_bytes();
        let mut bytes = Vec::with_capacity(24 + 4 + self.name.len() + 4 + canon_bytes.len());
        bytes.extend_from_slice(b"kinetic-auth-manifest-v1");
        bytes.extend_from_slice(&(self.name.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.name.as_bytes());
        bytes.extend_from_slice(&(canon_bytes.len() as u32).to_be_bytes());
        bytes.extend_from_slice(canon_bytes);
        bytes
    }
}

/// Loads an Ed25519 signing keypair from the specified file.
///
/// # Errors
///
/// Returns an `IdentityError` if the file is not found or is corrupted (e.g., incorrect length).
#[cfg(not(target_arch = "wasm32"))]
pub fn load_keypair(
    filename: &str,
) -> Result<ed25519_dalek::SigningKey, crate::error::IdentityError> {
    use directories::ProjectDirs;
    use std::fs;
    use std::path::PathBuf;

    let key_path = std::env::var("KINETIC_KEY_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            ProjectDirs::from("com", "kinetic", "kinetic")
                .map(|d| d.config_dir().join(filename))
                .unwrap_or_else(|| {
                    std::env::current_dir()
                        .unwrap_or_else(|_| PathBuf::from("."))
                        .join(format!(".kinetic/{}", filename))
                })
        });

    if key_path.exists() {
        let bytes = fs::read(&key_path)?;
        if bytes.len() == 32 {
            let mut array = [0u8; 32];
            array.copy_from_slice(&bytes);
            return Ok(ed25519_dalek::SigningKey::from_bytes(&array));
        } else {
            return Err(crate::error::IdentityError::CorruptedIdentityFile(
                format!("Expected 32 bytes, found {}. Please restore from a backup or manually delete the file to generate a new identity.", bytes.len())
            ));
        }
    }

    Err(crate::error::IdentityError::IdentityNotFound("Identity file not found. Please run 'kinetic-cli seed init' or use the Desktop app to create one.".to_string()))
}

/// Derives and saves an Ed25519 signing keypair from a mnemonic seed phrase.
///
/// # Errors
///
/// Returns an `IdentityError` if the seed phrase is invalid or if there is an error writing to disk.
#[cfg(not(target_arch = "wasm32"))]
pub fn save_keypair_from_mnemonic(
    filename: &str,
    phrase: &str,
) -> Result<ed25519_dalek::SigningKey, crate::error::IdentityError> {
    use bip39::{Language, Mnemonic};
    use directories::ProjectDirs;
    use pbkdf2::pbkdf2_hmac;
    use sha2::Sha512;
    use std::fs;
    use std::path::PathBuf;

    let mnemonic = Mnemonic::parse_in(Language::English, phrase)
        .map_err(|e| crate::error::IdentityError::InvalidSeedPhrase(format!("{}", e)))?;

    let seed = mnemonic.to_seed("");
    let mut derived = [0u8; 32];
    pbkdf2_hmac::<Sha512>(&seed, b"duckU", 2048, &mut derived);

    let signing_key = ed25519_dalek::SigningKey::from_bytes(&derived);

    let key_path = std::env::var("KINETIC_KEY_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            ProjectDirs::from("com", "kinetic", "kinetic")
                .map(|d| d.config_dir().join(filename))
                .unwrap_or_else(|| {
                    std::env::current_dir()
                        .unwrap_or_else(|_| PathBuf::from("."))
                        .join(format!(".kinetic/{}", filename))
                })
        });

    if let Some(parent) = key_path.parent() {
        let _ = fs::create_dir_all(parent);
    }

    let tmp_path = key_path.with_extension("tmp");
    fs::write(&tmp_path, signing_key.to_bytes())?;
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
        };
        let auth_kid = AuthorizedKid {
            name: "test.kin".to_string(),
            kid_doc: doc,
            owner_signature: vec![1, 2, 3],
        };

        let bytes = auth_kid.signable_bytes();
        assert!(bytes.starts_with(b"kinetic-auth-kid-v1"));
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
            services: vec![],
            signature: None,
        };
        let auth_manifest = AuthorizedManifest {
            name: "test.kin".to_string(),
            manifest,
            owner_signature: vec![1, 2, 3],
        };

        let bytes = auth_manifest.signable_bytes();
        assert!(bytes.starts_with(b"kinetic-auth-manifest-v1"));
        assert!(bytes.windows(8).any(|w| w == b"test.kin"));
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn test_identity_key_lifecycle() {
        // Run all key lifecycle tests synchronously in one function
        // to avoid race conditions with KINETIC_KEY_PATH env var
        let dir = tempdir().unwrap();

        // 1. Not Found
        std::env::set_var("KINETIC_KEY_PATH", dir.path().join("missing.bin"));
        let result = load_keypair("test.bin");
        assert!(matches!(
            result,
            Err(crate::error::IdentityError::IdentityNotFound(_))
        ));

        // 2. Corrupted File
        let corrupt_path = dir.path().join("corrupted.bin");
        fs::write(&corrupt_path, b"too_short").unwrap();
        std::env::set_var("KINETIC_KEY_PATH", &corrupt_path);
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
        std::env::set_var("KINETIC_KEY_PATH", &valid_path);
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let saved_key = save_keypair_from_mnemonic("test.bin", phrase).unwrap();
        let loaded_key = load_keypair("test.bin").unwrap();
        assert_eq!(saved_key.to_bytes(), loaded_key.to_bytes());

        // Clean up env var
        std::env::remove_var("KINETIC_KEY_PATH");
    }
}
