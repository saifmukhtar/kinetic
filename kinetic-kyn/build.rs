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
    
    let genesis = parsed["drand"]["drand_genesis_time"].as_u64().expect("drand_genesis_time missing");
    let period = parsed["drand"]["drand_period"].as_u64().expect("drand_period missing");
    let pubkey_hex = parsed["drand"]["drand_public_key"].as_str().expect("drand_public_key missing");

    // Decode hex
    let pubkey_bytes = (0..pubkey_hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&pubkey_hex[i..i + 2], 16).unwrap())
        .collect::<Vec<u8>>();

    let out_dir = std::env::var("OUT_DIR").unwrap();
    let dest_path = std::path::Path::new(&out_dir).join("network_constants.rs");
    
    let mut out = String::new();
    out.push_str(&format!("pub const DRAND_GENESIS_TIME: u64 = {};\n", genesis));
    out.push_str(&format!("pub const DRAND_PERIOD: u64 = {};\n", period));
    out.push_str(&format!("pub const DRAND_PUBLIC_KEY_BYTES: [u8; {}] = {:?};\n", pubkey_bytes.len(), pubkey_bytes));
    
    fs::write(&dest_path, out).expect("Failed to write network_constants.rs");
}
