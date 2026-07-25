//! # kinetic-keygen
//!
//! Offline governance key generator for the Kinetic network (`kinetic-keygen`).
//!
//! This binary is used **offline** by members of the Kinetic council to deterministically
//! derive their ML-DSA-65 (Dilithium3) keypair for governing the network. It must never be run on
//! an internet-connected machine when generating production keys.

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as b64, Engine as _};
use bip39::{Language, Mnemonic};
use chrono::Utc;
use clap::{Args, Parser, Subcommand};
use dialoguer::{Input, Password};
use getrandom::fill;
use ml_dsa::{KeyExport, Keypair, MlDsa65};
use pbkdf2::pbkdf2_hmac;
use sha2::{Digest, Sha256, Sha512};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(
    name = "kinetic-keygen",
    about = "Offline Post-Quantum Key Generator for Kinetic Governance"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new 24-word offline seed phrase and deterministic keys
    Generate(ExportArgs),
    /// Restore deterministic keys from an existing 24-word seed phrase
    Restore(ExportArgs),
    /// Verify a public key file (Hex or Base64) for integrity
    Verify {
        /// Path to the public key file
        file: String,
    },
}

#[derive(Args)]
struct ExportArgs {
    /// Optional base directory to export public key files (e.g., /media/usb)
    #[arg(short, long)]
    export: Option<String>,
}

fn derive_key(seed: &[u8], purpose: &str) -> ml_dsa::SigningKey<MlDsa65> {
    let mut derived_seed = [0u8; 32];
    pbkdf2_hmac::<Sha512>(
        seed,
        purpose.as_bytes(),
        kinetic_core::constants::CRYPTO_KEYGEN_PBKDF2_ITERATIONS,
        &mut derived_seed,
    );
    ml_dsa::SigningKey::<MlDsa65>::from_seed((&derived_seed).into())
}

struct VerificationData {
    length: usize,
    sha256: String,
    first_16: String,
    last_16: String,
}

fn calculate_verification_data(pubkey_bytes: &[u8]) -> VerificationData {
    let mut sha256_hasher = Sha256::new();
    sha256_hasher.update(pubkey_bytes);
    let sha256 = hex::encode(sha256_hasher.finalize());

    let len = pubkey_bytes.len();
    let first_16 = hex::encode(&pubkey_bytes[..std::cmp::min(16, len)]);
    let last_16 = hex::encode(&pubkey_bytes[len.saturating_sub(16)..]);

    VerificationData {
        length: len,
        sha256,
        first_16,
        last_16,
    }
}

fn print_and_export_keys(
    mnemonic: &Mnemonic,
    passphrase: &str,
    identity: &str,
    export_path: &Path,
    encrypt_pass: &str,
) -> Result<()> {
    let seed = mnemonic.to_seed(passphrase);
    let key = derive_key(
        &seed,
        kinetic_core::constants::KINETIC_GOVERNANCE_KEY_PURPOSE,
    );
    let pubkey_bytes = key.verifying_key().to_bytes();

    let pubkey_hex = hex::encode(pubkey_bytes);
    let pubkey_b64 = b64.encode(pubkey_bytes);
    let v_data = calculate_verification_data(&pubkey_bytes);

    println!("\n========================================================");
    println!("🚨 OFFLINE SEED PHRASE (STORE SECURELY ON PAPER) 🚨");
    println!("========================================================");
    println!("{}", mnemonic);
    println!(
        "\nOptional Passphrase: {}",
        if passphrase.is_empty() {
            "[None]"
        } else {
            "********"
        }
    );
    println!("========================================================\n");

    let date_created = Utc::now().format("%Y-%m-%d").to_string();

    if !export_path.exists() {
        fs::create_dir_all(export_path).context("Failed to create export directory")?;
    }

    fs::write(export_path.join("public_key.hex"), &pubkey_hex)
        .context("Failed to write hex file")?;
    fs::write(export_path.join("public_key.base64"), &pubkey_b64)
        .context("Failed to write base64 file")?;

    let mut priv_hasher = Sha256::new();
    priv_hasher.update(key.to_bytes());
    let priv_sha256 = hex::encode(priv_hasher.finalize());

    let manifest = format!(
        "Identifier: {}\nAlgorithm : ML-DSA-65\nLength    : {} bytes\nSHA256    : {}\nFirst 16  : {}\nLast 16   : {}\nCreated   : {}\nVersion   : kinetic-keygen v1.0\nPrivate Key SHA256: {}\n",
        identity, v_data.length, v_data.sha256, v_data.first_16, v_data.last_16, date_created, priv_sha256
    );
    fs::write(export_path.join("manifest.txt"), &manifest)
        .context("Failed to write manifest file")?;

    println!(
        "✅ Successfully exported key files to: {}",
        export_path.display()
    );

    if !encrypt_pass.is_empty() {
        use aes_gcm::{
            aead::{Aead, KeyInit},
            Aes256Gcm, Nonce,
        };
        use pbkdf2::pbkdf2_hmac;
        use sha2::{Sha256, Sha512};
        use std::fs::File;
        use std::io::Read;

        let mut salt = [0u8; 16];
        let mut nonce_bytes = [0u8; 12];
        let mut urandom = File::open("/dev/urandom").expect("Failed to open /dev/urandom");
        urandom.read_exact(&mut salt).expect("RNG failure");
        urandom.read_exact(&mut nonce_bytes).expect("RNG failure");

        let mut derived_key = [0u8; 32];
        pbkdf2_hmac::<Sha256>(encrypt_pass.as_bytes(), &salt, 5_000_000, &mut derived_key);

        let cipher = Aes256Gcm::new((&derived_key).into());
        let nonce = Nonce::from_slice(&nonce_bytes);

        let mut raw_seed = [0u8; 32];
        pbkdf2_hmac::<Sha512>(
            &mnemonic.to_seed(passphrase),
            kinetic_core::constants::KINETIC_GOVERNANCE_KEY_PURPOSE.as_bytes(),
            kinetic_core::constants::CRYPTO_KEYGEN_PBKDF2_ITERATIONS,
            &mut raw_seed,
        );

        let ciphertext = cipher
            .encrypt(nonce, raw_seed.as_ref())
            .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

        let mut final_payload = Vec::new();
        final_payload.extend_from_slice(&salt);
        final_payload.extend_from_slice(&nonce_bytes);
        final_payload.extend_from_slice(&ciphertext);

        fs::write(export_path.join("private_key.aes"), final_payload)
            .context("Failed to write AES file")?;
        println!(
            "🔒 Encrypted private key saved to: {}/private_key.aes\n",
            export_path.display()
        );
    }

    Ok(())
}

fn verify_file(file_path: &str) -> Result<()> {
    if file_path.ends_with(".aes") {
        let password = Password::new()
            .with_prompt("AES Private Key Password")
            .interact()
            .context("Failed to read password")?;

        let key =
            kinetic_core::types::identity::load_encrypted_keypair(Path::new(file_path), &password)
                .map_err(|e| anyhow::anyhow!("Failed to decrypt AES key: {}", e))?;

        let mut priv_hasher = Sha256::new();
        priv_hasher.update(key.to_bytes());
        let priv_sha256 = hex::encode(priv_hasher.finalize());

        println!("✅ ENCRYPTED PRIVATE KEY DECRYPTED AND VALIDATED");
        println!("Algorithm : ML-DSA-65");
        println!("Private Key SHA256: {}", priv_sha256);
        return Ok(());
    }

    let content = fs::read_to_string(file_path).context("Failed to read file")?;
    let content = content.trim().replace("\n", "").replace("\r", "");

    let decoded = if content.chars().all(|c| c.is_ascii_hexdigit()) && content.len() % 2 == 0 {
        hex::decode(&content).context("Failed to decode hex")?
    } else {
        b64.decode(&content).context("Failed to decode base64")?
    };

    if decoded.len() != 1952 {
        anyhow::bail!(
            "Invalid Length: Expected 1952 bytes, got {} bytes. File is corrupted or not a valid ML-DSA-65 public key.",
            decoded.len()
        );
    }

    let v_data = calculate_verification_data(&decoded);

    println!("✅ PUBLIC KEY VALIDATED");
    println!("Algorithm : ML-DSA-65");
    println!("Length    : {} bytes", v_data.length);
    println!("SHA256    : {}", v_data.sha256);
    println!("First 16  : {}", v_data.first_16);
    println!("Last 16   : {}\n", v_data.last_16);

    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Generate(args) => {
            let mut entropy = [0u8; 32];
            fill(&mut entropy).context("Failed to generate random entropy for mnemonic")?;
            let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy)
                .context("Failed to generate mnemonic from entropy")?;

            let passphrase = Password::new()
                .with_prompt("25th-word Passphrase")
                .allow_empty_password(true)
                .interact()
                .context("Failed to read 25th-word passphrase")?;

            let identity: String = Input::new()
                .with_prompt("Member Name / ID")
                .interact_text()
                .context("Failed to read member identity")?;

            let aes_pass = Password::new()
                .with_prompt("AES Private Key Password")
                .allow_empty_password(true)
                .interact()
                .context("Failed to read AES password")?;

            let base_dir = args.export.unwrap_or_else(|| ".".to_string());
            let export_path = PathBuf::from(base_dir).join(&identity);

            print_and_export_keys(&mnemonic, &passphrase, &identity, &export_path, &aes_pass)?;
        }
        Commands::Restore(args) => {
            let phrase = Password::new()
                .with_prompt("Enter 24-word seed phrase")
                .interact()
                .context("Failed to read seed phrase")?;

            let mnemonic = Mnemonic::parse_in(Language::English, &phrase)
                .map_err(|e| anyhow::anyhow!("Invalid seed phrase: {}", e))?;

            let passphrase = Password::new()
                .with_prompt("25th-word Passphrase")
                .allow_empty_password(true)
                .interact()
                .context("Failed to read 25th-word passphrase")?;

            let identity: String = Input::new()
                .with_prompt("Member Name / ID")
                .interact_text()
                .context("Failed to read member identity")?;

            let aes_pass = Password::new()
                .with_prompt("AES Private Key Password")
                .allow_empty_password(true)
                .interact()
                .context("Failed to read AES password")?;

            let base_dir = args.export.unwrap_or_else(|| ".".to_string());
            let export_path = PathBuf::from(base_dir).join(&identity);
            print_and_export_keys(&mnemonic, &passphrase, &identity, &export_path, &aes_pass)?;
        }
        Commands::Verify { file } => {
            verify_file(&file)?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bip39::Language;
    use ml_dsa::KeyExport;
    use std::fs;

    #[test]
    fn test_derive_key_consistency() {
        let seed = [1u8; 64];
        let key1 = derive_key(&seed, "TEST_PURPOSE");
        let key2 = derive_key(&seed, "TEST_PURPOSE");
        assert_eq!(key1.to_bytes(), key2.to_bytes());
    }

    #[test]
    fn test_derive_key_uniqueness_purpose() {
        let seed = [2u8; 64];
        let key1 = derive_key(&seed, "PURPOSE_A");
        let key2 = derive_key(&seed, "PURPOSE_B");
        assert_ne!(key1.to_bytes(), key2.to_bytes());
    }

    #[test]
    fn test_derive_key_uniqueness_seed() {
        let seed1 = [3u8; 64];
        let seed2 = [4u8; 64];
        let key1 = derive_key(&seed1, "TEST_PURPOSE");
        let key2 = derive_key(&seed2, "TEST_PURPOSE");
        assert_ne!(key1.to_bytes(), key2.to_bytes());
    }

    #[test]
    fn test_mnemonic_generation_and_restore() {
        let mut entropy = [0u8; 32];
        fill(&mut entropy).unwrap();
        let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy).unwrap();
        let phrase = mnemonic.to_string();

        let restored = Mnemonic::parse_in(Language::English, &phrase).unwrap();
        assert_eq!(mnemonic.to_seed(""), restored.to_seed(""));
    }

    #[test]
    fn test_invalid_mnemonic_restore() {
        let phrase = "invalid phrase that is definitely not twenty four words and not in wordlist";
        let result = Mnemonic::parse_in(Language::English, phrase);
        assert!(result.is_err());
    }

    #[test]
    fn test_verification_data_calculation() {
        let pubkey_bytes = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13,
        ];
        let v_data = calculate_verification_data(&pubkey_bytes);

        assert_eq!(v_data.length, 20);
        assert_eq!(
            v_data.sha256,
            "e7aebf577f60412f0312d442c70a1fa6148c090bf5bab404caec29482ae779e8"
        );
        assert_eq!(v_data.first_16, "000102030405060708090a0b0c0d0e0f");
        assert_eq!(v_data.last_16, "0405060708090a0b0c0d0e0f10111213");
    }

    #[test]
    fn test_verify_file_length_validation() {
        let tmp_dir = std::env::temp_dir().join("kinetic-keygen-test");
        let _ = fs::create_dir_all(&tmp_dir);

        let too_short = vec![0x00; 1951];
        let short_path = tmp_dir.join("short.hex");
        fs::write(&short_path, hex::encode(&too_short)).unwrap();
        assert!(verify_file(short_path.to_str().unwrap()).is_err());

        let too_long = vec![0x00; 1953];
        let long_path = tmp_dir.join("long.hex");
        fs::write(&long_path, hex::encode(&too_long)).unwrap();
        assert!(verify_file(long_path.to_str().unwrap()).is_err());

        let exact = vec![0x00; 1952];
        let exact_path = tmp_dir.join("exact.hex");
        fs::write(&exact_path, hex::encode(&exact)).unwrap();
        assert!(verify_file(exact_path.to_str().unwrap()).is_ok());

        fs::remove_dir_all(tmp_dir).unwrap();
    }
}
