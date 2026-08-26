//! CLI wizard for bootstrapping and scaffolding isolated private Kinetic networks (`network.json`).

use anyhow::{Context, Result};
use axum::{
    extract::State,
    response::Html,
    routing::{get, post},
    Json, Router,
};
use clap::Parser;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use tokio::sync::oneshot;

#[derive(Parser, Debug)]
#[command(author, version, about = "Kinetic Forge - White-label Network Generator")]
struct Args {
    /// Skip the GUI and use a provided network.json file directly
    #[arg(short, long)]
    config: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let mut config: serde_json::Value = if let Some(config_path) = args.config {
        println!("Reading config from {}...", config_path);
        let content = fs::read_to_string(&config_path)?;
        serde_json::from_str(&content)?
    } else {
        println!("🚀 Starting Kinetic Forge Web GUI...");

        let (tx, rx) = oneshot::channel::<serde_json::Value>();
        let tx = std::sync::Arc::new(tokio::sync::Mutex::new(Some(tx)));

        let app = Router::new()
            .route("/", get(serve_gui))
            .route("/forge", post(handle_forge))
            .with_state(tx);

        // Bind to PORT 0 to get a random open ephemeral port, preventing collisions!
        let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await?;
        let addr = listener.local_addr()?;
        
        let url = format!("http://{}", addr);
        println!("✅ Server bound successfully!");
        println!("🌐 Opening Web GUI at: {}", url);
        
        // Open the user's default browser automatically
        if let Err(_) = open::that(&url) {
            println!("⚠️ Could not open browser automatically. Please click the link above.");
        }

        // Run the server in a spawned task
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        // Block until the web GUI sends us the JSON config
        let config = rx.await?;
        
        // Shutdown the web server
        server.abort();
        
        config
    };

    let network_id = config["network"]["network_id"].as_str().unwrap_or("kinetic").to_string();

    println!("\n========================================");
    println!("🔥 FORGE INITIATED FOR: {}", network_id);
    println!("========================================\n");

    let target_dir = PathBuf::from(format!("./{}-network", network_id));
    
    if target_dir.exists() {
        println!("⚠️ Target directory {:?} already exists! Deleting it for a fresh clone...", target_dir);
        fs::remove_dir_all(&target_dir)?;
    }

    println!("📥 Cloning fresh Kinetic repository...");
    let status = Command::new("git")
        .arg("clone")
        .arg("https://github.com/saifmukhtar/kinetic.git")
        .arg(&target_dir)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()?;

    if !status.success() {
        anyhow::bail!("Failed to clone repository");
    }

    // Move into the new clone to patch its files
    std::env::set_current_dir(&target_dir)?;

    println!("🛠️  Patching network.json...");
    
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let drand_genesis = config["drand"]["drand_genesis_time"].as_u64().unwrap_or(0);
    let drand_period = config["drand"]["drand_period"].as_u64().unwrap_or(3);

    let kinetic_genesis_drand_kyn = if now > drand_genesis {
        (now - drand_genesis) / drand_period
    } else {
        0
    };

    // Dynamically inject the calculated genesis block Kyn
    config["drand"]["kinetic_genesis_drand_kyn"] = serde_json::json!(kinetic_genesis_drand_kyn);

    // Save the raw JSON payload straight to network.json!
    let new_content = serde_json::to_string_pretty(&config)?;
    fs::write("network.json", new_content)?;

    println!("🛠️  Patching Cargo.toml binary names...");
    patch_cargo_bin_names(&network_id)?;

    println!("🏗️  Compiling the customized Kinetic network binaries (this may take a few minutes)...");
    let build_status = Command::new("cargo")
        .arg("build")
        .arg("--release")
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()?;

    if build_status.success() {
        println!("\n🎉 FORGE COMPLETE 🎉");
        println!("Your custom network binaries have been compiled to: {:?}/target/release/", target_dir);
    } else {
        println!("❌ Build failed.");
    }

    Ok(())
}

// ==========================================
// AXUM WEB HANDLERS
// ==========================================

async fn serve_gui() -> Html<&'static str> {
    Html(include_str!("index.html"))
}

async fn handle_forge(
    State(tx): State<std::sync::Arc<tokio::sync::Mutex<Option<oneshot::Sender<serde_json::Value>>>>>,
    Json(payload): Json<serde_json::Value>,
) -> &'static str {
    // Take the sender out of the mutex and send the payload back to the main thread
    if let Some(sender) = tx.lock().await.take() {
        let _ = sender.send(payload);
    }
    "Success"
}

// ==========================================
// PATCHING LOGIC
// ==========================================

fn patch_cargo_bin_names(network_id: &str) -> Result<()> {
    let crates = vec![
        ("kinetic-daemon", format!("{}-daemon", network_id)),
        ("kinetic-node", format!("{}-node", network_id)),
        ("kinetic-keygen", format!("{}-keygen", network_id)),
        ("kinetic-kid", format!("{}-kid", network_id)),
        ("kinetic-host", format!("{}-host", network_id)),
        ("kinetic-pac", format!("{}-pac", network_id)),
        ("kinetic-dns", format!("{}-dns", network_id)),
        ("kinetic-cli", network_id.to_string()),
    ];

    for (crate_dir, new_bin_name) in crates {
        let path = PathBuf::from(crate_dir).join("Cargo.toml");
        if path.exists() {
            let content = fs::read_to_string(&path)?;
            let mut doc = content.parse::<toml_edit::DocumentMut>()?;

            if let Some(bin) = doc
                .get_mut("bin")
                .and_then(|i| i.as_array_of_tables_mut())
                .and_then(|arr| arr.iter_mut().next())
            {
                bin["name"] = toml_edit::value(new_bin_name.as_str());
            }

            fs::write(&path, doc.to_string())?;
            println!("   Patched {} [[bin]] name to {}", crate_dir, new_bin_name);
        }
    }
    Ok(())
}
