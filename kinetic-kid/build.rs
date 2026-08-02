use std::fs;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=../network.json");
    println!("cargo:rerun-if-env-changed=KINETIC_NETWORK_JSON");

    let network_json_path = std::env::var("KINETIC_NETWORK_JSON")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("../network.json"));
        
    if !network_json_path.exists() {
        panic!("network.json is missing. Please set KINETIC_NETWORK_JSON to the absolute path of network.json, or ensure it exists at ../network.json");
    }

    let json_content = fs::read_to_string(&network_json_path).expect("Failed to read network.json");
    let parsed: serde_json::Value =
        serde_json::from_str(&json_content).expect("Failed to parse network.json");
    let tld = parsed["network"]["tld"]
        .as_str()
        .expect("network.tld missing");
    let did_prefix = format!("did:{}:", tld);

    println!("cargo:rustc-env=KINETIC_DID_PREFIX={}", did_prefix);
}
