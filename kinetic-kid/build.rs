use std::fs;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=../network.json");

    let network_json_path = PathBuf::from("../network.json");
    if !network_json_path.exists() {
        panic!("network.json is missing from the workspace root.");
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
