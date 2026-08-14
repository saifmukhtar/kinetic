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
    let nsp = parsed["network"]["nsp"]
        .as_str()
        .expect("network.nsp missing");
    let did_prefix = format!("did:{}:", nsp);

    println!("cargo:rustc-env=KINETIC_DID_PREFIX={}", did_prefix);

    let max_public_key = parsed["advanced"]["limits"]["kid_max_public_key_bytes"]
        .as_u64()
        .unwrap_or(8192);
    let max_location = parsed["advanced"]["limits"]["kid_max_location_bytes"]
        .as_u64()
        .unwrap_or(2048);
    let max_endpoint = parsed["advanced"]["limits"]["kid_max_endpoint_bytes"]
        .as_u64()
        .unwrap_or(256);

    let out_dir = std::env::var("OUT_DIR").unwrap();
    let dest_path = std::path::Path::new(&out_dir).join("kid_limits.rs");
    let mut out = String::new();
    out.push_str(&format!("/// Maximum bytes for KID public key\npub const LIMITS_KID_MAX_PUBLIC_KEY_BYTES: usize = {};\n", max_public_key));
    out.push_str(&format!("/// Maximum bytes for KID location\npub const LIMITS_KID_MAX_LOCATION_BYTES: usize = {};\n", max_location));
    out.push_str(&format!("/// Maximum bytes for KID endpoint\npub const LIMITS_KID_MAX_ENDPOINT_BYTES: usize = {};\n", max_endpoint));
    fs::write(&dest_path, out).expect("Failed to write kid_limits.rs");
}
