//! # kinetic-keygen
//!
//! Offline governance key generator for the Kinetic network (`kinetic-keygen`).
//!
//! This binary is used **offline** by members of the Kinetic council to deterministically
//! derive their ML-DSA-65 (Dilithium3) keypair for governing the network. It must never be run on
//! an internet-connected machine when generating production keys.
//!
//! ## Commands
//!
//! - **`generate`** — Creates 32 bytes of OS-level cryptographic entropy,
//!   encodes it as a BIP-39 24-word English mnemonic, and derives a single governance
//!   key from it using PBKDF2-HMAC-SHA512.
//! - **`restore`** — Reproduces the exact same keypair from an existing
//!   24-word mnemonic, allowing recovery after hardware failure.
//!
//! ## Decentralization Note
//!
//! Every council member must run this utility independently to generate their own
//! 24-word seed phrase and derived key. No single entity should ever generate
//! or hold the seeds for multiple governance keys.

use anyhow::{Context, Result};
use bip39::{Language, Mnemonic};
use clap::{Parser, Subcommand};
use dialoguer::Password;
use getrandom::fill;
use ml_dsa::{KeyExport, Keypair, MlDsa65};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha512;

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
    Generate,
    /// Restore deterministic keys from an existing 24-word seed phrase
    Restore,
}

fn derive_key(seed: &[u8], purpose: &str) -> ml_dsa::SigningKey<MlDsa65> {
    // 1. Derive a 32-byte deterministic seed using PBKDF2
    let mut derived_seed = [0u8; 32];
    pbkdf2_hmac::<Sha512>(seed, purpose.as_bytes(), 2048, &mut derived_seed);

    // 2. Generate the ML-DSA-65 keypair deterministically using the derived seed
    ml_dsa::SigningKey::<MlDsa65>::from_seed((&derived_seed).into())
}

fn print_keys(mnemonic: &Mnemonic, passphrase: &str) {
    let seed = mnemonic.to_seed(passphrase);

    let key = derive_key(
        &seed,
        kinetic_core::constants::KINETIC_GOVERNANCE_KEY_PURPOSE,
    );

    println!("========================================================");
    println!("🚨 OFFLINE SEED PHRASE (STORE SECURELY - NEVER SHARE) 🚨");
    println!("========================================================");
    println!("{}", mnemonic);
    println!("========================================================");
    println!("Share this Public Key to be added to the Kinetic Council:");
    println!(
        "Public Key (Hex): {}",
        hex::encode(key.verifying_key().to_bytes())
    );
    println!("========================================================");
    println!("WARNING: Keep this Secret Key absolutely safe!");
    println!("Secret Key (Hex): {}", hex::encode(key.to_bytes()));
    println!("========================================================");
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Generate => {
            let mut entropy = [0u8; 32];
            fill(&mut entropy).context("Failed to generate random entropy for mnemonic")?;
            let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy)
                .context("Failed to generate mnemonic from entropy")?;

            let passphrase = Password::new()
                .with_prompt("Enter an optional 25th-word passphrase (leave blank for none)")
                .allow_empty_password(true)
                .interact()
                .context("Failed to read passphrase")?;

            print_keys(&mnemonic, &passphrase);
        }
        Commands::Restore => {
            let phrase = Password::new()
                .with_prompt("Enter your 24-word seed phrase")
                .interact()
                .context("Failed to read seed phrase")?;

            let passphrase = Password::new()
                .with_prompt("Enter your 25th-word passphrase (leave blank for none)")
                .allow_empty_password(true)
                .interact()
                .context("Failed to read passphrase")?;

            match Mnemonic::parse_in(Language::English, &phrase) {
                Ok(mnemonic) => {
                    print_keys(&mnemonic, &passphrase);
                }
                Err(e) => {
                    anyhow::bail!("Invalid seed phrase: {}", e);
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bip39::Language;
    use ml_dsa::KeyExport;

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
}
