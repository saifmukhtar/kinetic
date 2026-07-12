use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizedKid {
    pub name: String,
    pub kid_doc: kinetic_kid::document::KidDocument,
    pub owner_signature: Vec<u8>,
}

impl AuthorizedKid {
    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"kinetic-auth-kid-v1");
        bytes.extend_from_slice(self.name.as_bytes());
        if let Ok(canon) = self.kid_doc.canonicalize() {
            bytes.extend_from_slice(canon.as_bytes());
        }
        bytes
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizedManifest {
    pub name: String,
    pub manifest: kinetic_kid::manifest::CapabilityManifest,
    pub owner_signature: Vec<u8>,
}

impl AuthorizedManifest {
    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"kinetic-auth-manifest-v1");
        bytes.extend_from_slice(self.name.as_bytes());
        if let Ok(canon) = self.manifest.canonicalize() {
            bytes.extend_from_slice(canon.as_bytes());
        }
        bytes
    }
}

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

    let mnemonic = Mnemonic::parse_in(Language::English, phrase).map_err(|e| {
        crate::error::IdentityError::InvalidSeedPhrase(format!("{}", e))
    })?;

    let seed = mnemonic.to_seed("");
    let mut derived = [0u8; 32];
    pbkdf2_hmac::<Sha512>(&seed, b"KINETIC_NODE_KEY_v1", 2048, &mut derived);

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
