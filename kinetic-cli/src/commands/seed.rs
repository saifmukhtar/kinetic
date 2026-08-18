//! Seed phrase generation, interactive backup verification, and identity restoration CLI commands.

use bip39::{Language, Mnemonic};
use clap::Subcommand;
use getrandom::fill;
use kinetic_core::config::get_base_dir;
use kinetic_core::types::save_keypair_from_mnemonic;
use tracing::{info, warn};

/// Available subcommands for managing node seed phrases.
#[derive(Subcommand)]
pub enum SeedCommands {
    /// Generate a new master seed phrase and derive the node identity
    Init,
    /// Restore the node identity from an existing seed phrase
    Restore,
}

/// Dispatches seed-related CLI subcommands.
///
/// Handles initialization of new seed phrases and restoration of identities from existing phrases.
///
/// # Errors
/// Returns an `anyhow::Error` if:
/// - (Init) Entropy generation fails, the mnemonic cannot be created, or writing the identity to disk fails.
/// - (Restore) Reading the password interactively fails, or the mnemonic is invalid and fails to restore the identity.
pub async fn handle_seed_command(cmd: SeedCommands) -> anyhow::Result<()> {
    let identity_path = get_base_dir().join("identity.key");
    match cmd {
        SeedCommands::Init => {
            let mut entropy = [0u8; 32];
            fill(&mut entropy)
                .map_err(|e| anyhow::anyhow!("Failed to generate random entropy: {}", e))?;
            let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy)
                .map_err(|e| anyhow::anyhow!("Failed to generate mnemonic: {}", e))?;
            let phrase = mnemonic.to_string();

            println!("========================================================");
            println!("🚨 NEW IDENTITY CREATED - BACKUP IMMEDIATELY 🚨");
            println!("========================================================");
            println!("Write down this 24-word seed phrase and store it safely:\n");
            println!("{}", phrase);
            println!("\nWARNING: This is a one-way derivation. You will NEVER");
            println!("be able to view this phrase again.");
            println!("========================================================");

            let words: Vec<&str> = phrase.split_whitespace().collect();
            let idx1 = (entropy[0] % 24) as usize;
            let mut idx2 = (entropy[1] % 24) as usize;
            if idx1 == idx2 {
                idx2 = (idx2 + 1) % 24;
            }

            loop {
                use std::io::Write;
                print!("\nTo verify your backup, please enter word #{}: ", idx1 + 1);
                std::io::stdout().flush().unwrap();
                let mut input1 = String::new();
                std::io::stdin().read_line(&mut input1).unwrap();

                print!("Please enter word #{}: ", idx2 + 1);
                std::io::stdout().flush().unwrap();
                let mut input2 = String::new();
                std::io::stdin().read_line(&mut input2).unwrap();

                if input1.trim() == words[idx1] && input2.trim() == words[idx2] {
                    println!("\n✅ Seed phrase verified successfully!");
                    break;
                } else {
                    println!("\n❌ Incorrect words. Please check your backup and try again.");
                }
            }

            save_keypair_from_mnemonic(
                &identity_path.to_string_lossy(),
                &phrase,
                kinetic_core::constants::NETWORK_SALT,
            )?;
            info!("Identity derived and saved to {:?}", identity_path);
        }
        SeedCommands::Restore => {
            let phrase = rpassword::prompt_password("Enter your 24-word seed phrase: ")
                .map_err(|e| anyhow::anyhow!("Failed to read seed phrase: {}", e))?;

            info!("Attempting to restore identity from phrase...");
            match save_keypair_from_mnemonic(
                &identity_path.to_string_lossy(),
                &phrase,
                kinetic_core::constants::NETWORK_SALT,
            ) {
                Ok(_) => {
                    info!("Successfully restored identity to {:?}!", identity_path);
                }
                Err(e) => {
                    warn!("Failed to restore identity: {}", e);
                    anyhow::bail!("Restore failed.");
                }
            }
        }
    }
    Ok(())
}
