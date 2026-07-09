use bip39::{Language, Mnemonic};
use clap::Subcommand;
use getrandom::fill;
use kinetic_core::config::get_base_dir;
use kinetic_core::types::save_keypair_from_mnemonic;
use tracing::{info, warn};

#[derive(Subcommand)]
pub enum SeedCommands {
    /// Generate a new master seed phrase and derive the node identity
    Init,
    /// Restore the node identity from an existing seed phrase
    Restore {
        /// The 24-word seed phrase (in quotes)
        phrase: String,
    },
}

pub async fn handle_seed_command(cmd: SeedCommands) -> anyhow::Result<()> {
    let identity_path = get_base_dir().join("identity.key");
    match cmd {
        SeedCommands::Init => {
            let mut entropy = [0u8; 32];
            fill(&mut entropy).expect("Failed to generate random entropy");
            let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy)
                .expect("Failed to generate mnemonic");
            let phrase = mnemonic.to_string();

            println!("========================================================");
            println!("🚨 NEW IDENTITY CREATED - BACKUP IMMEDIATELY 🚨");
            println!("========================================================");
            println!("Write down this 24-word seed phrase and store it safely:\n");
            println!("{}", phrase);
            println!("\nWARNING: This is a one-way derivation. You will NEVER");
            println!("be able to view this phrase again.");
            println!("========================================================");

            save_keypair_from_mnemonic(&identity_path.to_string_lossy(), &phrase)?;
            info!("Identity derived and saved to {:?}", identity_path);
        }
        SeedCommands::Restore { phrase } => {
            info!("Attempting to restore identity from phrase...");
            match save_keypair_from_mnemonic(&identity_path.to_string_lossy(), &phrase) {
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
