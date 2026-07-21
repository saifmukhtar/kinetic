use anyhow::{Context, Result};
use dialoguer::{theme::ColorfulTheme, Confirm, Input};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};

#[derive(Serialize, Deserialize)]
struct NetworkConfig {
    tld: String,
    tld_suffix: String,
    did_prefix: String,
    base_domain: String,
    network_id: String,
    benchmark_base_iterations: u64,
    steal_target_rounds: u64,
    drand_genesis_time: u64,
    drand_period: u64,
    kinetic_genesis_drand_round: u64,
    drand_public_key: String,
    drand_http_endpoints: Vec<String>,
    docs_url: String,
    bootstrap_nodes: Vec<String>,
    m_redundancy: u64,
    governance_model: String,
}

fn main() -> Result<()> {
    println!("========================================");
    println!("      KINETIC NETWORK FORGE 🚀");
    println!("========================================");
    println!("Welcome to the Kinetic Forge! Let's scaffold your isolated private network.");
    println!(
        "This wizard will configure your custom network parameters and compile custom binaries."
    );
    println!();

    let network_name: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("What is the name of your private network? (e.g. University Network)")
        .interact_text()?;

    let tld: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("What is the top-level domain (TLD) for this network? (e.g. uni)")
        .interact_text()?;

    let base_domain: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("What is the base domain for this network? (e.g. uni.edu)")
        .interact_text()?;

    println!("\nGenerating cryptographic network identity...");

    // Hash the network name to create a unique P2P protocol isolation ID
    let mut hasher = Sha256::new();
    hasher.update(network_name.as_bytes());
    let hash_result = hasher.finalize();
    let network_id = hex::encode(&hash_result[..16]); // Use first 32 characters (16 bytes)
    let network_id_str = format!("{}-{}", tld, network_id);

    let tld_suffix = format!(".{}", tld);
    let did_prefix = format!("did:{}:", tld);

    println!("✅ Network ID generated: {}", network_id_str);
    println!("✅ TLD Suffix: {}", tld_suffix);
    println!("✅ DID Prefix: {}", did_prefix);
    println!();

    let docs_url: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Documentation & Error URL (e.g. https://docs.my-network.internal)")
        .default("https://kinetic.saifmukhtar.dev".to_string())
        .interact_text()?;

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
        let mut endpoint: String = Input::with_theme(&ColorfulTheme::default())
            .with_prompt("Drand HTTPS Endpoint (e.g. https://my-drand.internal)")
            .interact_text()?;

        while !endpoint.starts_with("https://") {
            println!(
                "⚠️ SECURITY: Custom Drand endpoints must use https:// to prevent MITM attacks."
            );
            endpoint = Input::with_theme(&ColorfulTheme::default())
                .with_prompt("Drand HTTPS Endpoint (e.g. https://my-drand.internal)")
                .interact_text()?;
        }
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

    let bootstrap_nodes: Vec<String> = vec![];

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    
    let kinetic_genesis_drand_round = if now > drand_genesis {
        (now - drand_genesis) / drand_period
    } else {
        0
    };

    println!();
    if !Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Ready to update network.json and compile?")
        .interact()?
    {
        println!("Aborting forge process. No changes made.");
        return Ok(());
    }

    println!("Updating network.json...");
    patch_constants(
        &tld,
        &tld_suffix,
        &did_prefix,
        &base_domain,
        &network_id_str,
        &drand_pubkey,
        drand_genesis,
        drand_period,
        kinetic_genesis_drand_round,
        &drand_http,
        &docs_url,
        &bootstrap_nodes,
    )?;

    println!("✅ network.json updated successfully.");
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
        println!();
        println!("⚠️ NEXT STEPS FOR BOOTSTRAPPING:");
        println!("1. Run your first `kinetic-node` (this will act as your seed node).");
        println!("2. Note its printed P2P Multiaddress (which includes its PeerId).");
        println!("3. For all subsequent nodes you deploy, you must manually add that first node's");
        println!(
            "   multiaddress to their `~/.local/share/kinetic/config.toml` under `bootstrap_nodes`."
        );
        println!("4. (Optional) Add the multiaddress to a DNS TXT record at your seed domain.");
        println!("========================================");
    } else {
        println!("❌ Build failed. Please check the compiler errors above.");
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn patch_constants(
    tld: &str,
    tld_suffix: &str,
    did_prefix: &str,
    base_domain: &str,
    network_id: &str,
    drand_pubkey: &str,
    drand_genesis: u64,
    drand_period: u64,
    kinetic_genesis_drand_round: u64,
    drand_http: &str,
    docs_url: &str,
    bootstrap_nodes: &[String],
) -> Result<()> {
    let path = PathBuf::from("network.json");

    let mut config: NetworkConfig = if path.exists() {
        let content = fs::read_to_string(&path).context(
            "Failed to read network.json. Are you running this from the workspace root?",
        )?;
        serde_json::from_str(&content).context("Failed to parse existing network.json")?
    } else {
        NetworkConfig {
            tld: String::new(),
            tld_suffix: String::new(),
            did_prefix: String::new(),
            base_domain: String::new(),
            network_id: String::new(),
            benchmark_base_iterations: 238819830,
            steal_target_rounds: 7884000,
            drand_genesis_time: 0,
            drand_period: 0,
            kinetic_genesis_drand_round: 0,
            drand_public_key: String::new(),
            drand_http_endpoints: vec![],
            docs_url: String::new(),
            bootstrap_nodes: vec![],
            m_redundancy: 32,
            governance_model: "bicameral".to_string(),
        }
    };

    config.tld = tld.to_string();
    config.tld_suffix = tld_suffix.to_string();
    config.did_prefix = did_prefix.to_string();
    config.base_domain = base_domain.to_string();
    config.network_id = network_id.to_string();
    config.drand_genesis_time = drand_genesis;
    config.drand_period = drand_period;
    config.kinetic_genesis_drand_round = kinetic_genesis_drand_round;
    config.drand_public_key = drand_pubkey.to_string();
    config.drand_http_endpoints = vec![drand_http.to_string()];
    config.docs_url = docs_url.to_string();
    config.bootstrap_nodes = bootstrap_nodes.to_vec();

    let new_content =
        serde_json::to_string_pretty(&config).context("Failed to serialize network config")?;
    fs::write(&path, new_content).context("Failed to write updated network.json")?;

    Ok(())
}
