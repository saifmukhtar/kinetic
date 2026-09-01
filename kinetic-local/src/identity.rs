use kinetic_core::error::IdentityError;
use kinetic_primitives::keys::KineticKeypair;
use std::path::Path;

#[cfg(not(target_arch = "wasm32"))]
pub fn load_keypair(path: &Path) -> Result<KineticKeypair, IdentityError> {
    use std::fs;
    let data = fs::read(path)
        .map_err(|e| IdentityError::IdentityNotFound(format!("{}: {:?}", e, path)))?;
    if data.len() < 32 {
        return Err(IdentityError::CorruptedIdentityFile(
            "File too short to contain a valid key".into(),
        ));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&data[..32]);
    Ok(KineticKeypair::from_seed(&seed))
}

#[cfg(not(target_arch = "wasm32"))]
pub fn load_encrypted_keypair(
    path: &Path,
    password: &str,
) -> Result<KineticKeypair, IdentityError> {
    use aes_gcm::{
        Aes256Gcm, Nonce,
        aead::{Aead, KeyInit},
    };
    use pbkdf2::pbkdf2_hmac;
    use sha2::Sha512;
    use std::fs;

    let data = fs::read(path)
        .map_err(|e| IdentityError::IdentityNotFound(format!("{}: {:?}", e, path)))?;

    if data.len() < 16 + 12 + 32 + 16 {
        return Err(IdentityError::CorruptedIdentityFile(
            "Encrypted file is too short".into(),
        ));
    }

    let salt = &data[0..16];
    let nonce_bytes = &data[16..28];
    let ciphertext = &data[28..];

    let mut derived_key = [0u8; 32];
    pbkdf2_hmac::<Sha512>(password.as_bytes(), salt, 600_000, &mut derived_key);

    let cipher = Aes256Gcm::new((&derived_key).into());
    let nonce = Nonce::from_slice(nonce_bytes);

    if let Ok(decrypted_seed) = cipher.decrypt(nonce, ciphertext)
        && decrypted_seed.len() == 32
    {
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&decrypted_seed);
        return Ok(KineticKeypair::from_seed(&seed));
    }

    Err(IdentityError::IdentityNotFound(format!(
        "Encrypted identity file not found at {:?}",
        path
    )))
}

#[cfg(not(target_arch = "wasm32"))]
pub fn save_keypair_from_mnemonic(
    key_path: &Path,
    phrase: &str,
    network_salt: &[u8; 32],
) -> Result<KineticKeypair, IdentityError> {
    use bip39::{Language, Mnemonic};
    use pbkdf2::pbkdf2_hmac;
    use sha2::Sha512;
    use std::fs;
    use zeroize::Zeroize;

    let mnemonic = Mnemonic::parse_in(Language::English, phrase)
        .map_err(|e| IdentityError::InvalidSeedPhrase(format!("{}", e)))?;

    let mut seed = mnemonic.to_seed("");

    let mut salt = Vec::with_capacity(32 + 12);
    salt.extend_from_slice(network_salt);
    salt.extend_from_slice(b"-seed-key-v1");

    let mut derived = [0u8; 32];
    #[cfg(debug_assertions)]
    let iterations = 1000;
    #[cfg(not(debug_assertions))]
    let iterations = 5_000_000;

    pbkdf2_hmac::<Sha512>(&seed, &salt, iterations, &mut derived);

    let signing_key = KineticKeypair::from_seed(&derived);

    seed.zeroize();
    derived.zeroize();

    if let Some(parent) = key_path.parent() {
        let _ = fs::create_dir_all(parent);
    }

    crate::secure_fs::write_secret(key_path, &signing_key.to_bytes())?;

    Ok(signing_key)
}
