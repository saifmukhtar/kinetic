use std::fs;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=../network.json");
    println!("cargo:rerun-if-env-changed=KINETIC_NETWORK_JSON");

    let env_path = std::env::var("KINETIC_NETWORK_JSON").map(PathBuf::from);
    let workspace_path = PathBuf::from("../network.json");
    let bundled_path = PathBuf::from("default_network.json");

    let network_json_path = if let Ok(path) = env_path {
        path
    } else if workspace_path.exists() {
        workspace_path
    } else if bundled_path.exists() {
        bundled_path
    } else {
        panic!("Failed to find network.json in any location.");
    };

    let json_content = fs::read_to_string(&network_json_path).expect("Failed to read network.json");
    let parsed: serde_json::Value =
        serde_json::from_str(&json_content).expect("Failed to parse network.json");
    let tld = parsed["network"]["tld"]
        .as_str()
        .expect("network.tld missing");
    let did_prefix = format!("did:{}:", tld);

    println!("cargo:rustc-env=KINETIC_DID_PREFIX={}", did_prefix);
}
