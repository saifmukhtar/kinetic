//! # kinetic-keygen
//!
//! Offline governance key generator for the Kinetic network (`kinetic-keygen`).
//!
//! This binary is used **offline** by the Kinetic council to deterministically
//! derive the Ed25519 keypairs that govern the network. It must never be run on
//! an internet-connected machine when generating production keys.
//!
//! ## Commands
//!
//! - **`generate`** — Creates 32 bytes of OS-level cryptographic entropy,
//!   encodes it as a BIP-39 24-word English mnemonic, and derives all council
//!   keys from it using PBKDF2-HMAC-SHA512 with 2048 iterations.
//! - **`restore`** — Reproduces the exact same keypairs from an existing
//!   24-word mnemonic, allowing recovery after hardware failure.
//!
//! ## Key derivation
//!
//! Each key role uses a unique purpose string as the PBKDF2 salt, ensuring
//! that the `ROOT_KEY`, `GUARD_KEY`, and each `MEMBER_KEY_N` are
//! cryptographically independent even though they share the same seed.

use anyhow::{Context, Result};
use bip39::{Language, Mnemonic};
use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use getrandom::fill;
use pbkdf2::pbkdf2_hmac;
use sha2::Sha512;

#[derive(Parser)]
#[command(
    name = "kinetic-keygen",
    about = "Offline Key Generator for Kinetic Governance"
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
    Restore {
        /// The 24-word seed phrase (in quotes)
        phrase: String,
    },
}

fn derive_key(seed: &[u8], purpose: &str) -> SigningKey {
    let mut derived = [0u8; 32];
    pbkdf2_hmac::<Sha512>(seed, purpose.as_bytes(), 2048, &mut derived);
    SigningKey::from_bytes(&derived)
}

fn print_keys(mnemonic: &Mnemonic) {
    let seed = mnemonic.to_seed("");

    let root_key = derive_key(&seed, "ROOT_KEY_v1");
    let guard_key = derive_key(&seed, "GUARD_KEY_v1");

    println!("========================================================");
    println!("🚨 OFFLINE SEED PHRASE (STORE SECURELY - NEVER SHARE) 🚨");
    println!("========================================================");
    println!("{}", mnemonic);
    println!("========================================================");
    println!("Update kinetic-core/src/governance.rs with these keys:");
    println!();
    println!(
        "pub const ROOT_PUBLIC_KEY_HEX: &str = \"{}\";",
        hex::encode(root_key.verifying_key().to_bytes())
    );
    println!(
        "pub const GUARD_PUBLIC_KEY_HEX: &str = \"{}\";",
        hex::encode(guard_key.verifying_key().to_bytes())
    );
    println!();
    println!("--- Member Keys (For Phase 1 Initial Council) ---");
    for i in 1..=3 {
        let member_key = derive_key(&seed, &format!("MEMBER_KEY_v1_{}", i));
        println!(
            "Member {}: {}",
            i,
            hex::encode(member_key.verifying_key().to_bytes())
        );
        println!(
            "  Secret (KEEP SAFE): {}",
            hex::encode(member_key.to_bytes())
        );
    }
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
            print_keys(&mnemonic);
        }
        Commands::Restore { phrase } => match Mnemonic::parse_in(Language::English, &phrase) {
            Ok(mnemonic) => {
                print_keys(&mnemonic);
            }
            Err(e) => {
                anyhow::bail!("Invalid seed phrase: {}", e);
            }
        },
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bip39::Language;

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
