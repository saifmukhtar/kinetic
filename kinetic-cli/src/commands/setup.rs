//! Interactive setup wizard for onboarding new Kinetic nodes and identities.

use clap::Parser;

/// Interactive setup wizard for new Kinetic users.
#[derive(Parser)]
pub struct SetupCommand;

/// Executes the interactive setup wizard for initial node configuration.
///
/// # Errors
/// Returns an `anyhow::Error` if the underlying seed phrase generation or identity writing fails.
pub async fn handle_setup_command(_cmd: SetupCommand) -> anyhow::Result<()> {
    println!("\n========================================================");
    println!("🌌 Welcome to Kinetic!");
    println!("Let's get your local environment configured.");
    println!("========================================================\n");

    // 1. Generate identity
    println!("Step 1: Generating your Node Identity");
    super::seed::handle_seed_command(super::seed::SeedCommands::Init).await?;

    // 2. Wrap up
    println!("\n========================================================");
    println!("🎉 Setup Complete!");
    println!("========================================================");
    println!("Your Kinetic environment is ready to go.");
    println!("\nNext Steps:");
    println!("  1. Start the Kinetic Daemon:   sudo systemctl start kinetic-daemon");
    println!("  2. Check your node status:     kinetic daemon status");
    println!("  3. Register your .kin domain:  kinetic name register <name.kin>");
    println!("\nFor documentation, visit https://kinetic.saifmukhtar.dev");
    println!("========================================================\n");

    Ok(())
}
