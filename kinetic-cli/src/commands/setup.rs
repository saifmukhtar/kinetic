//! Interactive setup wizard for onboarding new Kinetic nodes and identities.

use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// Interactive setup wizard for new Kinetic users.
#[derive(Parser)]
pub struct SetupCommand {
    #[command(subcommand)]
    pub target: Option<SetupTarget>,
}

#[derive(Subcommand)]
pub enum SetupTarget {
    /// Injects the Kinetic Root CA into Mozilla Firefox
    Firefox,
}

/// Executes the interactive setup wizard for initial node configuration.
///
/// # Errors
/// Returns an `anyhow::Error` if the underlying seed phrase generation or identity writing fails.
pub async fn handle_setup_command(cmd: SetupCommand) -> anyhow::Result<()> {
    if let Some(SetupTarget::Firefox) = cmd.target {
        return setup_firefox();
    }

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

fn setup_firefox() -> anyhow::Result<()> {
    println!("🦊 Kinetic Firefox NSS Configuration");
    println!("========================================================");

    let base_dir = kinetic_core::config::get_base_dir();
    let network_id = kinetic_core::constants::NETWORK_ID;
    let cert_path = base_dir.join(format!("{}.cert.pem", network_id));

    if !cert_path.exists() {
        println!("❌ Root CA not found at {}", cert_path.display());
        println!("Please start the Kinetic Daemon at least once to generate the Root CA.");
        return Ok(());
    }

    let mut profile_bases = vec![];
    if cfg!(windows) {
        profile_bases.push(
            PathBuf::from(std::env::var("APPDATA").unwrap_or_else(|_| "".to_string()))
                .join("Mozilla")
                .join("Firefox")
                .join("Profiles"),
        );
    } else if cfg!(target_os = "macos") {
        profile_bases.push(
            dirs::home_dir()
                .unwrap_or_default()
                .join("Library")
                .join("Application Support")
                .join("Firefox")
                .join("Profiles"),
        );
    } else {
        let home = dirs::home_dir().unwrap_or_default();
        profile_bases.push(home.join(".mozilla").join("firefox"));
        // Support XDG_CONFIG_HOME
        profile_bases.push(home.join(".config").join("mozilla").join("firefox"));
        // Support Flatpak
        profile_bases.push(
            home.join(".var")
                .join("app")
                .join("org.mozilla.Firefox")
                .join("config")
                .join("mozilla")
                .join("firefox"),
        );
        // Support Snap
        profile_bases.push(
            home.join("snap")
                .join("firefox")
                .join("common")
                .join(".mozilla")
                .join("firefox"),
        );
        // Support LibreWolf
        profile_bases.push(home.join(".librewolf"));
    };

    let mut found_any_profiles = false;
    for base in &profile_bases {
        if base.exists() {
            found_any_profiles = true;
            break;
        }
    }

    if !found_any_profiles {
        println!("❌ Firefox does not appear to be installed on this system.");
        println!("Checked common directories including flatpak and snap.");
        return Ok(());
    }

    println!("🔍 Checking for Mozilla NSS certutil...");

    // Check if certutil is installed
    let certutil_cmd = if cfg!(windows) {
        // On Windows, the native certutil does not work for NSS. We must ensure it's not the OS one.
        // We will assume they don't have it on Windows, because downloading NSS tools is rare.
        false
    } else {
        std::process::Command::new("certutil")
            .arg("-v")
            .output()
            .map(|o| {
                String::from_utf8_lossy(&o.stdout).contains("NSS")
                    || String::from_utf8_lossy(&o.stderr).contains("NSS")
            })
            .unwrap_or(false)
    };

    if certutil_cmd {
        println!("✅ Mozilla NSS certutil found! Injecting certificate...");

        // Find cert9.db profiles
        let mut injected = 0;
        for profile_base in profile_bases {
            if let Ok(entries) = std::fs::read_dir(&profile_base) {
                for entry in entries.flatten() {
                    let db_path = entry.path().join("cert9.db");
                    if db_path.exists() {
                        let status = std::process::Command::new("certutil")
                            .args([
                                "-A",
                                "-n",
                                "Kinetic Root CA",
                                "-t",
                                "TC,,",
                                "-i",
                                cert_path.to_str().unwrap(),
                                "-d",
                                &format!("sql:{}", entry.path().display()),
                            ])
                            .status();

                        if let Ok(s) = status {
                            if s.success() {
                                println!("   -> Injected into profile: {}", entry.path().display());
                                injected += 1;
                            }
                        }
                    }
                }
            }
        }

        if injected > 0 {
            println!("🎉 Success! The Kinetic Root CA has been securely injected into {} Firefox profile(s).", injected);
            println!("Firefox will now resolve .kin domains without security warnings.");
        } else {
            println!("⚠️ Found Firefox profiles, but none contained a cert9.db database.");
        }
    } else {
        println!("❌ Mozilla NSS tools are missing.\n");
        if cfg!(windows) {
            println!("To enable Kinetic domains in Firefox, please open Firefox, go to");
            println!("Settings -> Privacy & Security -> View Certificates -> Import");
            println!("and select the certificate located at:");
            println!("\n    {}\n", cert_path.display());
        } else if cfg!(target_os = "macos") {
            println!("To let Kinetic configure Firefox automatically, run `brew install nss` and rerun this command.");
            println!(
                "Alternatively, you can manually import the certificate in Firefox settings from:"
            );
            println!("\n    {}\n", cert_path.display());
        } else {
            let os_name = std::fs::read_to_string("/etc/os-release").unwrap_or_default();

            if os_name.to_lowercase().contains("ubuntu")
                || os_name.to_lowercase().contains("debian")
            {
                println!("Run `sudo apt install libnss3-tools` and rerun this command.");
            } else if os_name.to_lowercase().contains("fedora")
                || os_name.to_lowercase().contains("rhel")
                || os_name.to_lowercase().contains("centos")
            {
                println!("Run `sudo dnf install nss-tools` and rerun this command.");
            } else if os_name.to_lowercase().contains("arch")
                || os_name.to_lowercase().contains("manjaro")
            {
                println!("Run `sudo pacman -S nss` and rerun this command.");
            } else {
                println!("Please install the 'nss-tools' package using your OS package manager and rerun this command.");
            }

            println!("\nAlternatively, you can manually import the certificate in Firefox settings from:");
            println!("\n    {}\n", cert_path.display());
        }
    }

    Ok(())
}
