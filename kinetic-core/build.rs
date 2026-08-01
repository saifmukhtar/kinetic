use serde::Deserialize;
use std::env;
use std::fs;
use std::path::PathBuf;

#[derive(Deserialize)]
struct SquatterMultipliers {
    len_0_to_1: u64,
    len_2: u64,
    len_3: u64,
    len_4: u64,
    len_5: u64,
    len_6: u64,
    len_7: u64,
    len_8_to_10: u64,
    len_11_to_17: u64,
    len_18_to_20: u64,
}

#[derive(Deserialize)]
struct ConsensusConfig {
    vdf_squatter_multipliers: SquatterMultipliers,
    vdf_discount_min_iterations: u64,
    vdf_discount_percentage: u64,
    vdf_max_iterations: u64,
    vdf_max_proof_bytes: usize,
}

#[derive(Deserialize)]
struct LimitsConfig {
    p2p_max_packet_size: usize,
    p2p_max_circuit_bytes: usize,
    proxy_max_body_bytes: usize,
    storage_max_value_bytes: usize,
    kid_max_public_key_bytes: usize,
    kid_max_location_bytes: usize,
    kid_max_endpoint_bytes: usize,
    drand_max_response_bytes: usize,
    lru_cache_size: usize,
}

#[derive(Deserialize)]
struct TimeoutsConfig {
    idle_timeout_seconds: u64,
    heartbeat_age_warning_seconds: u64,
    heartbeat_age_critical_seconds: u64,
    dns_cache_ttl_seconds: u64,
    network_prune_interval_seconds: u64,
    host_route_max_age_seconds: u64,
}

#[derive(Deserialize)]
struct NetworkSection {
    tld: String,
    base_domain: String,
    network_id: String,
    docs_url: String,
    ipfs_gateway: Option<String>,
    local_bind_ip: String,
    bootstrap_nodes: Vec<String>,
}

#[derive(Deserialize)]
struct DrandSection {
    drand_genesis_time: u64,
    drand_period: u64,
    kinetic_genesis_drand_round: u64,
    drand_public_key: String,
    drand_http_endpoints: Vec<String>,
}

#[derive(Deserialize)]
struct GovernanceSection {
    governance_model: String,
    max_age_seconds: u64,
}

#[derive(Deserialize)]
struct AdvancedSection {
    benchmark_base_iterations: u64,
    benchmark_target_minutes: Option<f64>,
    steal_target_rounds: u64,
    m_redundancy: u8,
    dev_mode_iterations: u64,
    limits: LimitsConfig,
    timeouts: TimeoutsConfig,
}

#[derive(Deserialize)]
struct NetworkConfig {
    network: NetworkSection,
    drand: DrandSection,
    governance: GovernanceSection,
    consensus: ConsensusConfig,
    advanced: AdvancedSection,
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
        config.network.tld
    ));

    out.push_str(&format!(
        "/// The suffix format for Kinetic names, including the preceding dot.\npub const TLD_SUFFIX: &str = \".{}\";\n\n",
        config.network.tld
    ));

    out.push_str(&format!(
        "/// The prefix used for Decentralized Identifiers (DIDs) on the Kinetic network.\npub const DID_PREFIX: &str = \"did:{}:\";\n\n",
        config.network.tld
    ));

    out.push_str(&format!(
        "/// The base domain for network infrastructure (e.g. seeds, drand).\npub const BASE_DOMAIN: &str = \"{}\";\n\n",
        config.network.base_domain
    ));

    out.push_str(&format!(
        "/// The unique Network ID used to isolate P2P protocols.\npub const NETWORK_ID: &str = \"{}\";\n\n",
        config.network.network_id
    ));

    out.push_str(&format!(
        "/// Base hardware iteration anchor for the VDF. \n/// WARNING: If you want to connect to the global mainnet, you should NOT lower this much! \n/// It is carefully calibrated to prevent extreme spam across the global internet.\npub const BENCHMARK_BASE_ITERATIONS: u64 = {};\n\n",
        config.advanced.benchmark_base_iterations
    ));

    let target_minutes = config.advanced.benchmark_target_minutes.unwrap_or(30.0);
    out.push_str(&format!(
        "/// The physical time (in minutes) corresponding to the BENCHMARK_BASE_ITERATIONS.\npub const BENCHMARK_TARGET_MINUTES: f64 = {:.1};\n\n",
        target_minutes
    ));

    out.push_str(&format!(
        "/// The number of rounds a name must be inactive before the steal difficulty completely decays.\npub const STEAL_TARGET_ROUNDS: u64 = {};\n\n",
        config.advanced.steal_target_rounds
    ));

    // Safety floor: refuse to compile a network with fewer than 5 redundant DHT keys.
    // Below this threshold, Eclipse attack resistance degrades significantly.
    if config.advanced.m_redundancy < 5 {
        panic!(
            "network.json: m_redundancy={} is too low. Minimum is 5. \
             Below this threshold Eclipse attack resistance degrades significantly. \
             The canonical .kin mainnet uses 32.",
            config.advanced.m_redundancy
        );
    }
    out.push_str(&format!(
        "/// Number of independent DHT keys each name is stored under (Eclipse resistance).\n\
         /// WARNING: Do NOT lower this below 5 — Eclipse attack probability rises catastrophically.\n\
         /// The canonical .kin mainnet uses 32. Small trusted forks may use 8-16.\n\
         pub const M_REDUNDANCY: u8 = {};\n\n",
        config.advanced.m_redundancy
    ));

    out.push_str(&format!(
        "/// The swappable governance engine used by this network.\n\
         pub const GOVERNANCE_MODEL: &str = \"{}\";\n\n",
        config.governance.governance_model
    ));

    let local_bind_ip = &config.network.local_bind_ip;

    out.push_str(&format!(
        "/// The local IP address where local node services (DNS, Proxy) bind.\npub const LOCAL_BIND_IP: &str = \"{}\";\n\n",
        local_bind_ip
    ));

    out.push_str(&format!(
        "/// The maximum time (in seconds) a governance proposal is valid before it expires.\npub const MAX_AGE_SECONDS: u64 = {};\n\n",
        config.governance.max_age_seconds
    ));



    out.push_str(&format!(
        "/// The default number of iterations used during development and simulation mode.\npub const DEV_MODE_ITERATIONS: u64 = {};\n\n",
        config.advanced.dev_mode_iterations
    ));

    out.push_str(&format!(
        "/// Unix timestamp of the Drand chain's genesis.\npub const DRAND_GENESIS_TIME: u64 = {};\n\n",
        config.drand.drand_genesis_time
    ));

    out.push_str(&format!(
        "/// Duration in seconds of each Drand round.\npub const DRAND_PERIOD: u64 = {};\n\n",
        config.drand.drand_period
    ));

    out.push_str(&format!(
        "/// The absolute Drand round at which this network officially launched.\n/// Used purely for cosmetic frontend timekeeping (Epoch/Cycle/Pulse).\npub const KINETIC_GENESIS_DRAND_ROUND: u64 = {};\n\n",
        config.drand.kinetic_genesis_drand_round
    ));

    out.push_str(&format!(
        "/// The absolute Unix timestamp (in seconds) of the Kinetic network genesis.\npub const KINETIC_GENESIS_TIME: u64 = {};\n\n",
        config.drand.drand_genesis_time + (config.drand.kinetic_genesis_drand_round * config.drand.drand_period)
    ));

    // Expose NETWORK_ID as a compile-time env var so constants.rs can use env!() for
    // fork-isolated gossip topics and DB key prefixes without requiring a generated file.
    println!(
        "cargo:rustc-env=KINETIC_NETWORK_ID={}",
        config.network.network_id
    );
    println!(
        "cargo:rustc-env=KINETIC_NETWORK_ID_UPPER={}",
        config.network.network_id.to_uppercase()
    );

    out.push_str(&format!(
        "/// The League of Entropy public key for the Quicknet chain (or custom beacon).\npub const DRAND_PUBLIC_KEY: &str = \"{}\";\n\n",
        config.drand.drand_public_key
    ));

    out.push_str("/// The set of Drand HTTP endpoints tried in order.\npub const DRAND_HTTP_ENDPOINTS: &[&str] = &[\n");
    for endpoint in config.drand.drand_http_endpoints {
        out.push_str(&format!("    \"{}\",\n", endpoint));
    }
    out.push_str("];\n\n");

    out.push_str(&format!(
        "/// The URL for documentation and error lookups.\npub const DOCS_URL: &str = \"{}\";\n\n",
        config.network.docs_url
    ));

    out.push_str("/// The default P2P bootstrap nodes for joining the Kinetic DHT.\npub const BOOTSTRAP_NODES: &[&str] = &[\n");
    for node in config.network.bootstrap_nodes {
        out.push_str(&format!("    \"{}\",\n", node));
    }
    out.push_str("];\n\n");

    let default_ipfs_gateway = config
        .network
        .ipfs_gateway
        .unwrap_or_else(|| format!("https://ipfs.{}/ipfs/", config.network.base_domain));
    out.push_str(&format!(
        "/// The default public IPFS gateway used by the network proxy.\npub const IPFS_GATEWAY: &str = \"{}\";\n\n",
        default_ipfs_gateway
    ));

    out.push_str(&format!(
        "/// Multiplier for squatter cliff length 0 to 1\npub const CONSENSUS_SQUATTER_LEN_0_TO_1: u64 = {};\n", config.consensus.vdf_squatter_multipliers.len_0_to_1
    ));
    out.push_str(&format!(
        "/// Multiplier for squatter cliff length 2\npub const CONSENSUS_SQUATTER_LEN_2: u64 = {};\n", config.consensus.vdf_squatter_multipliers.len_2
    ));
    out.push_str(&format!(
        "/// Multiplier for squatter cliff length 3\npub const CONSENSUS_SQUATTER_LEN_3: u64 = {};\n", config.consensus.vdf_squatter_multipliers.len_3
    ));
    out.push_str(&format!(
        "/// Multiplier for squatter cliff length 4\npub const CONSENSUS_SQUATTER_LEN_4: u64 = {};\n", config.consensus.vdf_squatter_multipliers.len_4
    ));
    out.push_str(&format!(
        "/// Multiplier for squatter cliff length 5\npub const CONSENSUS_SQUATTER_LEN_5: u64 = {};\n", config.consensus.vdf_squatter_multipliers.len_5
    ));
    out.push_str(&format!(
        "/// Multiplier for squatter cliff length 6\npub const CONSENSUS_SQUATTER_LEN_6: u64 = {};\n", config.consensus.vdf_squatter_multipliers.len_6
    ));
    out.push_str(&format!(
        "/// Multiplier for squatter cliff length 7\npub const CONSENSUS_SQUATTER_LEN_7: u64 = {};\n", config.consensus.vdf_squatter_multipliers.len_7
    ));
    out.push_str(&format!(
        "/// Multiplier for squatter cliff length 8 to 10\npub const CONSENSUS_SQUATTER_LEN_8_TO_10: u64 = {};\n", config.consensus.vdf_squatter_multipliers.len_8_to_10
    ));
    out.push_str(&format!(
        "/// Multiplier for squatter cliff length 11 to 17\npub const CONSENSUS_SQUATTER_LEN_11_TO_17: u64 = {};\n", config.consensus.vdf_squatter_multipliers.len_11_to_17
    ));
    out.push_str(&format!(
        "/// Multiplier for squatter cliff length 18 to 20\npub const CONSENSUS_SQUATTER_LEN_18_TO_20: u64 = {};\n\n", config.consensus.vdf_squatter_multipliers.len_18_to_20
    ));

    out.push_str(&format!("/// Minimum iterations for VDF discount\npub const CONSENSUS_VDF_DISCOUNT_MIN_ITERATIONS: u64 = {};\n", config.consensus.vdf_discount_min_iterations));
    out.push_str(&format!("/// Discount percentage for VDF iterations\npub const CONSENSUS_VDF_DISCOUNT_PERCENTAGE: u64 = {};\n", config.consensus.vdf_discount_percentage));
    out.push_str(&format!(
        "/// Maximum iterations for VDF\npub const CONSENSUS_VDF_MAX_ITERATIONS: u64 = {};\n",
        config.consensus.vdf_max_iterations
    ));
    out.push_str(&format!("/// Maximum bytes for a VDF proof\npub const CONSENSUS_VDF_MAX_PROOF_BYTES: usize = {};\n\n", config.consensus.vdf_max_proof_bytes));



    out.push_str(&format!(
        "/// Maximum P2P packet size\npub const LIMITS_P2P_MAX_PACKET_SIZE: usize = {};\n",
        config.advanced.limits.p2p_max_packet_size
    ));
    out.push_str(&format!(
        "/// Maximum P2P circuit bytes\npub const LIMITS_P2P_MAX_CIRCUIT_BYTES: usize = {};\n",
        config.advanced.limits.p2p_max_circuit_bytes
    ));
    out.push_str(&format!(
        "/// Maximum proxy body bytes\npub const LIMITS_PROXY_MAX_BODY_BYTES: usize = {};\n",
        config.advanced.limits.proxy_max_body_bytes
    ));
    out.push_str(&format!(
        "/// Maximum storage value bytes\npub const LIMITS_STORAGE_MAX_VALUE_BYTES: usize = {};\n",
        config.advanced.limits.storage_max_value_bytes
    ));
    out.push_str(&format!("/// Maximum KID public key bytes\npub const LIMITS_KID_MAX_PUBLIC_KEY_BYTES: usize = {};\n", config.advanced.limits.kid_max_public_key_bytes));
    out.push_str(&format!(
        "/// Maximum KID location bytes\npub const LIMITS_KID_MAX_LOCATION_BYTES: usize = {};\n",
        config.advanced.limits.kid_max_location_bytes
    ));
    out.push_str(&format!(
        "/// Maximum KID endpoint bytes\npub const LIMITS_KID_MAX_ENDPOINT_BYTES: usize = {};\n",
        config.advanced.limits.kid_max_endpoint_bytes
    ));
    out.push_str(&format!("/// Maximum Drand response bytes\npub const LIMITS_DRAND_MAX_RESPONSE_BYTES: usize = {};\n", config.advanced.limits.drand_max_response_bytes));
    out.push_str(&format!(
        "/// Size of LRU caches\npub const LIMITS_LRU_CACHE_SIZE: usize = {};\n\n",
        config.advanced.limits.lru_cache_size
    ));

    out.push_str(&format!(
        "/// Idle timeout in seconds\npub const TIMEOUTS_IDLE_TIMEOUT_SECONDS: u64 = {};\n",
        config.advanced.timeouts.idle_timeout_seconds
    ));
    out.push_str(&format!("/// Heartbeat age warning threshold in seconds\npub const TIMEOUTS_HEARTBEAT_AGE_WARNING_SECONDS: u64 = {};\n", config.advanced.timeouts.heartbeat_age_warning_seconds));
    out.push_str(&format!("/// Heartbeat age critical threshold in seconds\npub const TIMEOUTS_HEARTBEAT_AGE_CRITICAL_SECONDS: u64 = {};\n", config.advanced.timeouts.heartbeat_age_critical_seconds));
    out.push_str(&format!(
        "/// DNS cache TTL in seconds\npub const TIMEOUTS_DNS_CACHE_TTL_SECONDS: u64 = {};\n",
        config.advanced.timeouts.dns_cache_ttl_seconds
    ));
    out.push_str(&format!("/// Network prune interval in seconds\npub const TIMEOUTS_NETWORK_PRUNE_INTERVAL_SECONDS: u64 = {};\n", config.advanced.timeouts.network_prune_interval_seconds));
    out.push_str(&format!("/// Maximum age of a host route in seconds\npub const TIMEOUTS_HOST_ROUTE_MAX_AGE_SECONDS: u64 = {};\n", config.advanced.timeouts.host_route_max_age_seconds));

    fs::write(&dest_path, out).expect("Failed to write network_constants.rs");
}
