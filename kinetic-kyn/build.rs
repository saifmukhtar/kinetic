use serde_json::Value;
use std::env;
use std::fs;
use std::path::Path;

fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    // Path to network.json in the workspace root
    let network_json_path = Path::new(&manifest_dir).join("../network.json");

    if network_json_path.exists() {
        let content = fs::read_to_string(&network_json_path).expect("Failed to read network.json");
        let parsed: Value = serde_json::from_str(&content).expect("Failed to parse network.json");

        if let Some(oracle) = parsed.get("time_oracle") {
            if let Some(genesis_time) = oracle.get("beacon_genesis").and_then(|v| v.as_u64()) {
                println!("cargo:rustc-env=BEACON_GENESIS={}", genesis_time);
            }
            if let Some(period) = oracle.get("kyn_period").and_then(|v| v.as_u64()) {
                println!("cargo:rustc-env=KYN_PERIOD={}", period);
            }
            if let Some(kyn_genesis) = oracle.get("kyn_genesis").and_then(|v| v.as_u64()) {
                println!("cargo:rustc-env=KYN_GENESIS={}", kyn_genesis);
            }
            if let Some(public_key) = oracle.get("beacon_public_key").and_then(|v| v.as_str()) {
                println!("cargo:rustc-env=BEACON_PUBLIC_KEY={}", public_key);
            }
        }

        // Inform Cargo to rerun this build script if network.json changes
        println!("cargo:rerun-if-changed={}", network_json_path.display());
    }
}
