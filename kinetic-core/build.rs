use serde::Deserialize;
use std::env;
use std::fs;
use std::path::PathBuf;

#[derive(Deserialize)]
struct NetworkConfig {
    tld: String,
    tld_suffix: String,
    did_prefix: String,
    base_domain: String,
    network_id: String,
    benchmark_base_iterations: u64,
    steal_target_rounds: u64,
    m_redundancy: u8,
    drand_genesis_time: u64,
    drand_period: u64,
    kinetic_genesis_drand_round: u64,
    drand_public_key: String,
    drand_http_endpoints: Vec<String>,
    docs_url: String,
    bootstrap_nodes: Vec<String>,
    governance_model: String,
}

fn main() {
    println!("cargo:rerun-if-changed=../network.json");

    let network_json_path = PathBuf::from("../network.json");
    if !network_json_path.exists() {
        panic!("network.json is missing from the workspace root. Please create it or run kinetic-forge to generate one.");
    }

    let json_content = fs::read_to_string(&network_json_path).expect("Failed to read network.json");
    let config: NetworkConfig =
        serde_json::from_str(&json_content).expect("Failed to parse network.json");

    let out_dir = env::var_os("OUT_DIR").unwrap();
    let dest_path = PathBuf::from(out_dir).join("network_constants.rs");

    let mut out = String::new();

    out.push_str(&format!(
        "/// The default Top Level Domain (TLD) for the Kinetic network.\npub const TLD: &str = \"{}\";\n\n",
        config.tld
    ));

    out.push_str(&format!(
        "/// The suffix format for Kinetic names, including the preceding dot.\npub const TLD_SUFFIX: &str = \"{}\";\n\n",
        config.tld_suffix
    ));

    out.push_str(&format!(
        "/// The prefix used for Decentralized Identifiers (DIDs) on the Kinetic network.\npub const DID_PREFIX: &str = \"{}\";\n\n",
        config.did_prefix
    ));

    out.push_str(&format!(
        "/// The base domain for network infrastructure (e.g. seeds, drand).\npub const BASE_DOMAIN: &str = \"{}\";\n\n",
        config.base_domain
    ));

    out.push_str(&format!(
        "/// The unique Network ID used to isolate P2P protocols.\npub const NETWORK_ID: &str = \"{}\";\n\n",
        config.network_id
    ));

    out.push_str(&format!(
        "/// Base hardware iteration anchor for the VDF. \n/// WARNING: If you want to connect to the global mainnet, you should NOT lower this much! \n/// It is carefully calibrated to prevent extreme spam across the global internet.\npub const BENCHMARK_BASE_ITERATIONS: u64 = {};\n\n",
        config.benchmark_base_iterations
    ));

    out.push_str(&format!(
        "/// The number of rounds a name must be inactive before the steal difficulty completely decays.\npub const STEAL_TARGET_ROUNDS: u64 = {};\n\n",
        config.steal_target_rounds
    ));

    // Safety floor: refuse to compile a network with fewer than 5 redundant DHT keys.
    // Below this threshold, Eclipse attack resistance degrades significantly.
    if config.m_redundancy < 5 {
        panic!(
            "network.json: m_redundancy={} is too low. Minimum is 5. \
             Below this threshold Eclipse attack resistance degrades significantly. \
             The canonical .kin mainnet uses 32.",
            config.m_redundancy
        );
    }
    out.push_str(&format!(
        "/// Number of independent DHT keys each name is stored under (Eclipse resistance).\n\
         /// WARNING: Do NOT lower this below 5 — Eclipse attack probability rises catastrophically.\n\
         /// The canonical .kin mainnet uses 32. Small trusted forks may use 8-16.\n\
         pub const M_REDUNDANCY: u8 = {};\n\n",
        config.m_redundancy
    ));

    out.push_str(&format!(
        "/// The swappable governance engine used by this network.\n\
         pub const GOVERNANCE_MODEL: &str = \"{}\";\n\n",
        config.governance_model
    ));

    out.push_str(&format!(
        "/// Unix timestamp of the Drand chain's genesis.\npub const DRAND_GENESIS_TIME: u64 = {};\n\n",
        config.drand_genesis_time
    ));

    out.push_str(&format!(
        "/// Duration in seconds of each Drand round.\npub const DRAND_PERIOD: u64 = {};\n\n",
        config.drand_period
    ));

    out.push_str(&format!(
        "/// The absolute Drand round at which this network officially launched.\n/// Used purely for cosmetic frontend timekeeping (Epoch/Cycle/Pulse).\npub const KINETIC_GENESIS_DRAND_ROUND: u64 = {};\n\n",
        config.kinetic_genesis_drand_round
    ));

    out.push_str(&format!(
        "/// The League of Entropy public key for the Quicknet chain (or custom beacon).\npub const DRAND_PUBLIC_KEY: &str = \"{}\";\n\n",
        config.drand_public_key
    ));

    out.push_str("/// The set of Drand HTTP endpoints tried in order.\npub const DRAND_HTTP_ENDPOINTS: &[&str] = &[\n");
    for endpoint in config.drand_http_endpoints {
        out.push_str(&format!("    \"{}\",\n", endpoint));
    }
    out.push_str("];\n\n");

    out.push_str(&format!(
        "/// The URL for documentation and error lookups.\npub const DOCS_URL: &str = \"{}\";\n\n",
        config.docs_url
    ));

    out.push_str("/// The default P2P bootstrap nodes for joining the Kinetic DHT.\npub const BOOTSTRAP_NODES: &[&str] = &[\n");
    for node in config.bootstrap_nodes {
        out.push_str(&format!("    \"{}\",\n", node));
    }
    out.push_str("];\n");

    fs::write(&dest_path, out).expect("Failed to write network_constants.rs");
}
