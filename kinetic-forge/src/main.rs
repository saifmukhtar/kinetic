use anyhow::{Context, Result};
use dialoguer::{theme::ColorfulTheme, Input, Confirm};
use regex::Regex;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};

fn main() -> Result<()> {
    println!("========================================");
    println!("      KINETIC NETWORK FORGE 🚀");
    println!("========================================");
    println!("Welcome to the Kinetic Forge! Let's scaffold your isolated private network.");
    println!("This wizard will rewrite your core constants and compile custom binaries.");
    println!();

    let network_name: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("What is the name of your private network? (e.g. University Network)")
        .interact_text()?;

    let tld: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("What is the top-level domain (TLD) for this network? (e.g. uni)")
        .interact_text()?;

    let seed_domain: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("What is the bootstrap seed domain? (e.g. seed.uni.edu)")
        .interact_text()?;

    let drand_domain: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("What is the Drand beacon domain? (e.g. drand.uni.edu)")
        .interact_text()?;

    println!("\nGenerating cryptographic network identity...");
    
    // Hash the network name to create a unique P2P protocol isolation ID
    let mut hasher = Sha256::new();
    hasher.update(network_name.as_bytes());
    let hash_result = hasher.finalize();
    let network_id = hex::encode(&hash_result[..4]); // Use first 8 characters
    let network_id_str = format!("{}-{}", tld, network_id);

    let tld_suffix = format!(".{}", tld);
    let did_prefix = format!("did:{}:", tld);

    println!("✅ Network ID generated: {}", network_id_str);
    println!("✅ TLD Suffix: {}", tld_suffix);
    println!("✅ DID Prefix: {}", did_prefix);
    println!();

    if !Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Ready to inject these constants into the source code and compile?")
        .interact()?
    {
        println!("Aborting forge process. No changes made.");
        return Ok(());
    }

    println!("Patching kinetic-core/src/constants.rs...");
    patch_constants(&tld, &tld_suffix, &did_prefix, &seed_domain, &drand_domain, &network_id_str)?;
    
    println!("✅ Source code patched successfully.");
    println!("Compiling the customized Kinetic network binaries (this may take a few minutes)...");
    
    let mut child = Command::new("cargo")
        .arg("build")
        .arg("--release")
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .context("Failed to spawn cargo build")?;

    let status = child.wait().context("Failed to wait on cargo build")?;
    
    if status.success() {
        println!("========================================");
        println!("🎉 FORGE COMPLETE 🎉");
        println!("Your custom network binaries have been compiled to target/release/");
        println!("You can now deploy kinetic-daemon, kinetic-host, and kinetic-dns!");
    } else {
        println!("❌ Build failed. Please check the compiler errors above.");
    }

    Ok(())
}

fn patch_constants(
    tld: &str,
    tld_suffix: &str,
    did_prefix: &str,
    seed_domain: &str,
    drand_domain: &str,
    network_id: &str,
) -> Result<()> {
    // Navigate to kinetic-core/src/constants.rs
    // Assuming kinetic-forge is run from the workspace root
    let path = PathBuf::from("kinetic-core/src/constants.rs");
    
    let content = fs::read_to_string(&path)
        .context("Failed to read kinetic-core/src/constants.rs. Are you running this from the workspace root?")?;

    let mut new_content = content.clone();

    // Regex replacement for TLD
    let re_tld = Regex::new(r#"pub const TLD: &str = "[^"]*";"#)?;
    new_content = re_tld.replace(&new_content, format!(r#"pub const TLD: &str = "{}";"#, tld)).into_owned();

    // Regex replacement for TLD_SUFFIX
    let re_tld_suffix = Regex::new(r#"pub const TLD_SUFFIX: &str = "[^"]*";"#)?;
    new_content = re_tld_suffix.replace(&new_content, format!(r#"pub const TLD_SUFFIX: &str = "{}";"#, tld_suffix)).into_owned();

    // Regex replacement for DID_PREFIX
    let re_did_prefix = Regex::new(r#"pub const DID_PREFIX: &str = "[^"]*";"#)?;
    new_content = re_did_prefix.replace(&new_content, format!(r#"pub const DID_PREFIX: &str = "{}";"#, did_prefix)).into_owned();

    // Regex replacement for SEED_DOMAIN
    let re_seed_domain = Regex::new(r#"pub const SEED_DOMAIN: &str = "[^"]*";"#)?;
    new_content = re_seed_domain.replace(&new_content, format!(r#"pub const SEED_DOMAIN: &str = "{}";"#, seed_domain)).into_owned();

    // Regex replacement for DRAND_DOMAIN
    let re_drand_domain = Regex::new(r#"pub const DRAND_DOMAIN: &str = "[^"]*";"#)?;
    new_content = re_drand_domain.replace(&new_content, format!(r#"pub const DRAND_DOMAIN: &str = "{}";"#, drand_domain)).into_owned();

    // Regex replacement for NETWORK_ID
    let re_network_id = Regex::new(r#"pub const NETWORK_ID: &str = "[^"]*";"#)?;
    new_content = re_network_id.replace(&new_content, format!(r#"pub const NETWORK_ID: &str = "{}";"#, network_id)).into_owned();

    fs::write(&path, new_content).context("Failed to write updated constants.rs")?;

    Ok(())
}
