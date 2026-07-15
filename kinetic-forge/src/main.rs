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

    let use_public_drand = Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Do you want to use the public Quicknet Drand beacon (Recommended)?")
        .default(true)
        .interact()?;

    let (drand_pubkey, drand_genesis, drand_period, drand_http) = if !use_public_drand {
        println!("\n--- Custom Private Drand Configuration ---");
        let pk: String = Input::with_theme(&ColorfulTheme::default())
            .with_prompt("Drand Public Key (Hex)")
            .interact_text()?;
        let genesis: u64 = Input::with_theme(&ColorfulTheme::default())
            .with_prompt("Drand Genesis Time (Unix Timestamp)")
            .interact_text()?;
        let period: u64 = Input::with_theme(&ColorfulTheme::default())
            .with_prompt("Drand Round Period (Seconds)")
            .interact_text()?;
        let endpoint: String = Input::with_theme(&ColorfulTheme::default())
            .with_prompt("Drand HTTP Endpoint (e.g. http://my-drand.internal)")
            .interact_text()?;
        (pk, genesis, period, endpoint)
    } else {
        (
            "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a".to_string(),
            1692803367,
            3,
            "https://api.drand.sh/52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971/public/latest".to_string()
        )
    };

    println!();
    if !Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Ready to inject these constants into the source code and compile?")
        .interact()?
    {
        println!("Aborting forge process. No changes made.");
        return Ok(());
    }

    println!("Patching kinetic-core/src/constants.rs...");
    patch_constants(
        &tld, &tld_suffix, &did_prefix, &seed_domain, &drand_domain, &network_id_str,
        &drand_pubkey, drand_genesis, drand_period, &drand_http
    )?;
    
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
    drand_pubkey: &str,
    drand_genesis: u64,
    drand_period: u64,
    drand_http: &str,
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

    // Regex replacements for Drand
    let re_drand_genesis = Regex::new(r#"pub const DRAND_GENESIS_TIME: u64 = \d+;"#)?;
    new_content = re_drand_genesis.replace(&new_content, format!(r#"pub const DRAND_GENESIS_TIME: u64 = {};"#, drand_genesis)).into_owned();

    let re_drand_period = Regex::new(r#"pub const DRAND_PERIOD: u64 = \d+;"#)?;
    new_content = re_drand_period.replace(&new_content, format!(r#"pub const DRAND_PERIOD: u64 = {};"#, drand_period)).into_owned();

    let re_drand_pubkey = Regex::new(r#"pub const DRAND_PUBLIC_KEY: &str = "[^"]*";"#)?;
    new_content = re_drand_pubkey.replace(&new_content, format!(r#"pub const DRAND_PUBLIC_KEY: &str = "{}";"#, drand_pubkey)).into_owned();

    // Replaces the entire DRAND_HTTP_ENDPOINTS array block
    let re_drand_endpoints = Regex::new(r#"(?s)pub const DRAND_HTTP_ENDPOINTS: &\[&str\] = &\[.*?\];"#)?;
    new_content = re_drand_endpoints.replace(&new_content, format!(r#"pub const DRAND_HTTP_ENDPOINTS: &[&str] = &["{}"];"#, drand_http)).into_owned();

    fs::write(&path, new_content).context("Failed to write updated constants.rs")?;

    Ok(())
}
