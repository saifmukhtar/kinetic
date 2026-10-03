use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::path::PathBuf;

#[derive(Deserialize)]
struct NetworkConfig {
    network: NetworkSection,
    beacon: BeaconSection,
}

#[derive(Deserialize)]
struct NetworkSection {
    nsp: String,
    local_bind_ip: String,
}

#[derive(Deserialize)]
struct BeaconSection {
    beacon_genesis: u64,
    beacon_public_key: String,
}

fn main() {
    println!("cargo:rerun-if-changed=../network.json");
    println!("cargo:rerun-if-changed=../kinetic-core/src/constants.rs");

    // Read network.json
    let workspace_path = PathBuf::from("../network.json");
    if !workspace_path.exists() {
        panic!("kinetic-env build script requires network.json at workspace root");
    }

    let json_content = fs::read_to_string(&workspace_path).expect("Failed to read network.json");
    let config: NetworkConfig =
        serde_json::from_str(&json_content).expect("Failed to parse network.json");

    // Extract ROOT_KEY from kinetic-core constants
    let constants_src = fs::read_to_string("../kinetic-core/src/constants.rs")
        .expect("Failed to read kinetic-core/src/constants.rs");
    let prod_key = extract_root_key(&constants_src, "prod_keys");

    // Compute PROD salt
    let mut hasher = Sha256::new();
    hasher.update(prod_key.as_bytes());
    hasher.update(config.beacon.beacon_public_key.as_bytes());
    hasher.update(config.beacon.beacon_genesis.to_be_bytes());
    let prod_salt = hasher.finalize();
    
    let salt_prefix = &hex::encode(prod_salt)[..4];

    // Write to OUT_DIR
    let out_dir = env::var_os("OUT_DIR").unwrap();
    let dest_path = PathBuf::from(out_dir).join("env_constants.rs");

    let mut out = String::new();
    out.push_str(&format!(
        "pub const NSP: &str = \"{}\";\n",
        config.network.nsp
    ));
    out.push_str(&format!(
        "pub const SALT_PREFIX: &str = \"{}\";\n",
        salt_prefix
    ));
    out.push_str(&format!(
        "pub const NETWORK_SALT_HEX: &str = \"{}\";\n",
        hex::encode(prod_salt)
    ));
    out.push_str(&format!(
        "pub const NETWORK_SALT: [u8; 32] = {:?};\n",
        prod_salt.as_slice()
    ));
    out.push_str(&format!(
        "pub const LOCAL_BIND_IP: &str = \"{}\";\n",
        config.network.local_bind_ip
    ));

    fs::write(&dest_path, out).expect("Failed to write env_constants.rs");
}

fn extract_root_key(src: &str, module_name: &str) -> String {
    let mod_start = src
        .find(&format!("pub mod {}", module_name))
        .unwrap_or_else(|| panic!("Could not find {} module in constants.rs", module_name));

    let key_marker = "pub const SOVEREIGN_KEY_HEX: &str = \"";
    let key_start = src[mod_start..]
        .find(key_marker)
        .unwrap_or_else(|| panic!("Could not find SOVEREIGN_KEY_HEX in {}", module_name))
        + mod_start
        + key_marker.len();

    let key_end = src[key_start..]
        .find("\"")
        .unwrap_or_else(|| panic!("Malformed ROOT_PUBLIC_KEY_HEX in {}", module_name))
        + key_start;

    src[key_start..key_end].to_string()
}
