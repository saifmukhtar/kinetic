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
/// Returns an `anyhow::Error` if entropy generation fails, the mnemonic cannot be created/parsed,
/// or writing the resulting identity to disk fails.
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

            save_keypair_from_mnemonic(&identity_path.to_string_lossy(), &phrase)?;
            info!("Identity derived and saved to {:?}", identity_path);
        }
        SeedCommands::Restore => {
            let phrase = rpassword::prompt_password("Enter your 24-word seed phrase: ")
                .map_err(|e| anyhow::anyhow!("Failed to read seed phrase: {}", e))?;

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
