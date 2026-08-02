//! Global configuration models, default values, and port definitions for Kinetic.
//!
//! This module defines `KineticConfig`, which represents the complete runtime
//! configuration loaded from disk (`config.toml`) or environment variables.
//!
//! ## Configuration Resolution Order
//!
//! 1. **Explicit file path**: `KINETIC_CONFIG_PATH` environment variable.
//! 2. **Default user path**: `~/.local/share/{NETWORK_ID}/config.toml` (or platform equivalent via `get_base_dir`).
//! 3. **Fallback defaults**: If the file does not exist, a clean default config is automatically written to disk.
//!
//! ## Port Allocation Strategy
//!
//! All default port assignments are centralized in the `ports` submodule to ensure
//! zero collisions between `kinetic-daemon`, `kinetic-node`, and `kinetic-host`.

use serde::{Deserialize, Serialize};
#[cfg(not(target_arch = "wasm32"))]
use std::fs;
use std::path::PathBuf;
/// Maximum age in seconds (10 minutes) for cached host routing records in proxy forwarding.
/// Well-known default network port assignments for Kinetic binaries.
///
/// Centralizing port assignments here prevents accidental conflicts
/// between the daemon, node, and host processes on a single system.
pub mod ports {
    /// Default P2P listen port for `kinetic-daemon` (6070).
    pub const P2P_DAEMON: u16 = 6070;
    /// Default P2P listen port for `kinetic-node` (6071).
    pub const P2P_NODE: u16 = 6071;
    /// Default P2P listen port for `kinetic-host` (6072).
    pub const P2P_HOST: u16 = 6072;

    /// Default authenticated HTTP API port for `kinetic-daemon` (16002).
    pub const API_DAEMON: u16 = 16002;
    /// Default HTTP health-check port for `kinetic-node` (16003).
    pub const API_NODE: u16 = 16003;
    /// Default HTTP health-check port for `kinetic-host` (16004).
    pub const API_HOST: u16 = 16004;

    /// Default HTTP reverse-proxy port for intercepting `.kin` requests (17001).
    pub const PROXY: u16 = 17001;
    /// Default UDP DNS resolver port for native OS queries (53).
    pub const DNS: u16 = 53;
    /// Default local backend HTTP port (80).
    pub const BACKEND: u16 = 80;
    /// Default Proxy Auto-Config (PAC) server port (16001).
    pub const PAC: u16 = 16001;
}

/// Primary configuration container for Kinetic nodes and daemons.
///
/// Holds settings for daemon behavior, P2P networking, and Drand beacon connections.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KineticConfig {
    /// Daemon-level settings: ports, storage path, and network mode.
    pub daemon: DaemonConfig,
    /// P2P networking settings: ports, bootstrap nodes, and mDNS.
    pub network: P2pConfig,
    /// Drand randomness beacon settings: custom endpoints and DNS seed.
    #[serde(default)]
    pub drand: DrandConfig,
}

/// Drand networking configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DrandConfig {
    /// Drand HTTP endpoints to query for Quicknet pulses.
    #[serde(
        default = "default_drand_endpoints",
        skip_serializing_if = "is_default_drand_endpoints"
    )]
    pub endpoints: Vec<String>,
    /// Domains to query via DNS TXT records for dynamic Drand endpoints.
    #[serde(default = "default_drand_seed_domain")]
    pub drand_domain: Vec<String>,
    /// If true, the node will only listen to P2P gossipsub for Drand pulses
    /// and will not query the internet via HTTP/DNS.
    #[serde(default)]
    pub p2p_only: bool,
}

fn default_drand_endpoints() -> Vec<String> {
    crate::constants::DRAND_HTTP_ENDPOINTS
        .iter()
        .map(|s| s.to_string())
        .collect()
}

fn is_default_drand_endpoints(val: &Vec<String>) -> bool {
    val == &default_drand_endpoints()
}

fn default_drand_seed_domain() -> Vec<String> {
    vec![format!("drand.{}", crate::constants::BASE_DOMAIN)]
}

impl Default for DrandConfig {
    fn default() -> Self {
        Self {
            endpoints: default_drand_endpoints(),
            drand_domain: default_drand_seed_domain(),
            p2p_only: false,
        }
    }
}

/// Daemon-specific configuration: API ports, storage paths, and operating mode.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonConfig {
    /// Local IP address to bind to for daemon services.
    #[serde(default = "local_bind_ip", skip_serializing_if = "is_default_bind_ip")]
    pub bind_ip: String,
    /// IP address used by the PAC script and the proxy.
    #[serde(default = "default_pac_bind_ip")]
    pub pac_bind_ip: String,
    /// Port for the daemon's authenticated HTTP API (default: [`ports::API_DAEMON`]).
    #[serde(
        default = "default_api_port",
        skip_serializing_if = "is_default_api_port"
    )]
    pub api_port: u16,
    /// Port for the built-in DNS resolver (default: [`ports::DNS`]).
    #[serde(default = "default_dns_port")]
    pub dns_port: u16,
    /// Port for the built-in HTTP reverse proxy (default: [`ports::PROXY`]).
    #[serde(default = "default_proxy_port")]
    pub proxy_port: u16,
    /// Port for the local backend HTTP server (default: [`ports::BACKEND`]).
    #[serde(
        default = "default_backend_port",
        skip_serializing_if = "is_default_backend_port"
    )]
    pub backend_port: u16,
    /// Whether to start the built-in UDP DNS resolver on boot (default: `true`).
    #[serde(default = "default_true")]
    pub enable_dns: bool,
    /// Path to the directory where the embedded storage database is persisted.
    pub storage_dir: PathBuf,
    /// Network operating mode. Supported values: `"FullNode"` (participates in DHT storage & routing)
    /// or `"LightClient"` (queries network without storing records).
    #[serde(default = "default_network_mode")]
    pub network_mode: String,
    /// Whether the node should automatically download and install OTA binary updates.
    #[serde(default = "default_auto_update")]
    pub auto_update: bool,
    /// Port for the PAC (Proxy Auto-Config) server (default: [`ports::PAC`]).
    #[serde(
        default = "default_pac_port",
        skip_serializing_if = "is_default_pac_port"
    )]
    pub pac_port: u16,
    /// IPFS gateway URL used to resolve `IPFS(cid)` records in the HTTP Proxy.
    #[serde(default = "default_ipfs_gateway")]
    pub ipfs_gateway: String,
    /// UDP port for querying the Kinetic Atlas Bridge daemon (default: `34291`).
    #[serde(default = "default_atlas_port")]
    pub atlas_port: u16,
}

fn local_bind_ip() -> String {
    crate::constants::LOCAL_BIND_IP.to_string()
}

fn default_pac_bind_ip() -> String {
    crate::constants::LOCAL_BIND_IP.to_string()
}

fn is_default_bind_ip(val: &String) -> bool {
    val == crate::constants::LOCAL_BIND_IP
}

fn default_true() -> bool {
    true
}

fn default_auto_update() -> bool {
    true
}

fn default_network_mode() -> String {
    "FullNode".to_string()
}

fn default_api_port() -> u16 {
    ports::API_DAEMON
}

fn default_dns_port() -> u16 {
    ports::DNS
}

fn default_proxy_port() -> u16 {
    ports::PROXY
}

fn default_backend_port() -> u16 {
    ports::BACKEND
}

fn default_pac_port() -> u16 {
    ports::PAC
}

fn is_default_api_port(val: &u16) -> bool {
    *val == ports::API_DAEMON
}
fn is_default_backend_port(val: &u16) -> bool {
    *val == ports::BACKEND
}
fn is_default_pac_port(val: &u16) -> bool {
    *val == ports::PAC
}

fn default_atlas_port() -> u16 {
    34291
}

fn default_ipfs_gateway() -> String {
    crate::constants::IPFS_GATEWAY.to_string()
}

/// P2P networking configuration shared across all Kinetic binaries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct P2pConfig {
    /// P2P listen port for the daemon (default: [`ports::P2P_DAEMON`]).
    #[serde(
        default = "default_p2p_daemon",
        skip_serializing_if = "is_default_p2p_daemon"
    )]
    pub daemon_port: u16,
    /// P2P listen port for the daemon over QUIC (default: [`ports::P2P_DAEMON`]).
    #[serde(
        default = "default_p2p_daemon_quic",
        skip_serializing_if = "is_default_p2p_daemon_quic"
    )]
    pub daemon_quic_port: u16,
    /// P2P listen port for the node (default: [`ports::P2P_NODE`]).
    #[serde(
        default = "default_p2p_node",
        skip_serializing_if = "is_default_p2p_node"
    )]
    pub node_port: u16,
    /// P2P listen port for the node over QUIC (default: [`ports::P2P_NODE`]).
    #[serde(
        default = "default_p2p_node_quic",
        skip_serializing_if = "is_default_p2p_node_quic"
    )]
    pub node_quic_port: u16,
    /// P2P listen port for the host (default: [`ports::P2P_HOST`]).
    #[serde(
        default = "default_p2p_host",
        skip_serializing_if = "is_default_p2p_host"
    )]
    pub host_port: u16,
    /// P2P listen port for the host over QUIC (default: [`ports::P2P_HOST`]).
    #[serde(
        default = "default_p2p_host_quic",
        skip_serializing_if = "is_default_p2p_host_quic"
    )]
    pub host_quic_port: u16,
    /// Multiaddr strings for the initial bootstrap peers.
    pub bootstrap_nodes: Vec<String>,
    /// `.kin` domain names used to discover additional bootstrap peers via DNS.
    #[serde(default)]
    pub seed_domain: Vec<String>,
    /// Whether to enable mDNS peer discovery on the local network.
    #[serde(default = "default_true")]
    pub enable_mdns: bool,
    /// Optional externally reachable multiaddr (e.g. for nodes behind NAT).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_address: Option<String>,
}

fn default_p2p_daemon() -> u16 {
    ports::P2P_DAEMON
}

fn default_p2p_daemon_quic() -> u16 {
    ports::P2P_DAEMON
}

fn default_p2p_node() -> u16 {
    ports::P2P_NODE
}

fn default_p2p_node_quic() -> u16 {
    ports::P2P_NODE
}

fn default_p2p_host() -> u16 {
    ports::P2P_HOST
}

fn default_p2p_host_quic() -> u16 {
    ports::P2P_HOST
}

fn is_default_p2p_daemon(val: &u16) -> bool {
    *val == ports::P2P_DAEMON
}
fn is_default_p2p_daemon_quic(val: &u16) -> bool {
    *val == ports::P2P_DAEMON
}
fn is_default_p2p_node(val: &u16) -> bool {
    *val == ports::P2P_NODE
}
fn is_default_p2p_node_quic(val: &u16) -> bool {
    *val == ports::P2P_NODE
}
fn is_default_p2p_host(val: &u16) -> bool {
    *val == ports::P2P_HOST
}
fn is_default_p2p_host_quic(val: &u16) -> bool {
    *val == ports::P2P_HOST
}

impl Default for KineticConfig {
    fn default() -> Self {
        #[cfg(not(target_arch = "wasm32"))]
        let storage_dir = crate::config::get_base_dir().join("db");

        #[cfg(target_arch = "wasm32")]
        let storage_dir = PathBuf::from("/kinetic-db");

        Self {
            daemon: DaemonConfig {
                bind_ip: crate::constants::LOCAL_BIND_IP.to_string(),
                pac_bind_ip: crate::constants::LOCAL_BIND_IP.to_string(),
                api_port: ports::API_DAEMON,
                dns_port: ports::DNS,
                proxy_port: ports::PROXY,
                backend_port: ports::BACKEND,
                enable_dns: true,
                storage_dir,
                network_mode: "FullNode".to_string(),
                auto_update: true,
                pac_port: ports::PAC,
                ipfs_gateway: crate::constants::IPFS_GATEWAY.to_string(),
                atlas_port: 34291,
            },
            network: P2pConfig {
                daemon_port: ports::P2P_DAEMON,
                daemon_quic_port: ports::P2P_DAEMON,
                node_port: ports::P2P_NODE,
                node_quic_port: ports::P2P_NODE,
                host_port: ports::P2P_HOST,
                host_quic_port: ports::P2P_HOST,
                bootstrap_nodes: crate::constants::BOOTSTRAP_NODES
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
                seed_domain: vec![format!("seed.{}", crate::constants::BASE_DOMAIN)],
                enable_mdns: true,
                external_address: None,
            },
            drand: DrandConfig::default(),
        }
    }
}

impl KineticConfig {
    /// Loads runtime configuration from disk (`config.toml`) or environment variables.
    ///
    /// Resolution Order:
    /// 1. Checks `KINETIC_CONFIG_PATH` environment variable.
    /// 2. Defaults to `get_base_dir().join("config.toml")`.
    /// 3. If missing, writes default configuration to disk and returns default settings.
    ///
    /// # Security & Fail-Closed Behavior
    ///
    /// If `config.toml` exists but contains invalid TOML syntax or corrupted fields, this method
    /// logs a critical error and aborts execution via `std::process::exit(1)`. This prevents
    /// "fail-open" security vulnerabilities where invalid configs silently degrade to insecure defaults.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn load() -> Self {
        let config_path = std::env::var(crate::constants::ENV_KINETIC_CONFIG_PATH)
            .map(PathBuf::from)
            .unwrap_or_else(|_| crate::config::get_base_dir().join("config.toml"));

        let config = match fs::read_to_string(&config_path) {
            Ok(config_str) => match toml::from_str(&config_str) {
                Ok(config) => config,
                Err(e) => {
                    tracing::error!("Failed to parse config.toml: {}. Refusing to start to avoid fail-open vulnerability.", e);
                    std::process::exit(1);
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Create default config only if it doesn't exist
                let default_cfg = Self::default();
                if let Some(parent) = config_path.parent() {
                    let _ = fs::create_dir_all(parent);
                    if let Ok(toml_str) = toml::to_string_pretty(&default_cfg) {
                        let _ = fs::write(&config_path, toml_str);
                    }
                }
                default_cfg
            }
            Err(e) => {
                tracing::error!("Failed to read config.toml: {}. Refusing to start to avoid fail-open vulnerability.", e);
                std::process::exit(1);
            }
        };

        config
    }

    #[cfg(target_arch = "wasm32")]
    /// Stub implementation for loading configuration in Wasm environments.
    pub fn load() -> Self {
        Self::default()
    }

    /// Serializes and writes the current configuration back to `config.toml`.
    ///
    /// # Errors
    ///
    /// Returns [`std::io::Error`] if file creation, TOML serialization, or writing fails.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn save(&self) -> Result<(), std::io::Error> {
        let config_path = std::env::var(crate::constants::ENV_KINETIC_CONFIG_PATH)
            .map(PathBuf::from)
            .unwrap_or_else(|_| crate::config::get_base_dir().join("config.toml"));

        if let Some(parent) = config_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let toml_str = toml::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        fs::write(&config_path, toml_str)
    }

    #[cfg(target_arch = "wasm32")]
    /// Stub implementation for saving configuration in Wasm environments.
    pub fn save(&self) -> Result<(), std::io::Error> {
        Ok(())
    }
}

/// Returns `true` if compile-time simulation mode is enabled (`cfg!(feature = "simulation")`).
///
/// Mathematically guarantees that dev-mode mocks cannot be activated in release builds.
pub fn is_dev_mode() -> bool {
    cfg!(feature = "simulation")
}

/// Returns the path to the directory where local zone JSON files are stored (`{base_dir}/zones`).
pub fn get_zones_dir() -> PathBuf {
    get_base_dir().join("zones")
}

/// Returns the platform-appropriate base directory for Kinetic data files.
///
/// Automatically namespaced by `{TLD}-{NETWORK_ID}` (e.g. `~/.local/share/kinetic/`)
/// to ensure multiple network instances or forks coexist without disk collisions.
/// Overrideable with the `KINETIC_DATA_DIR` environment variable.
pub fn get_base_dir() -> PathBuf {
    if let Ok(path) = std::env::var(crate::constants::ENV_KINETIC_DATA_DIR) {
        return PathBuf::from(path);
    }

    let network_dir = crate::constants::NETWORK_ID;

    #[cfg(not(target_arch = "wasm32"))]
    {
        dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(network_dir)
    }

    #[cfg(target_arch = "wasm32")]
    {
        PathBuf::from(format!("/{}", network_dir))
    }
}

/// Returns the path to the directory where the scoped CLI API token files are stored (`{base_dir}/tokens/`).
pub fn get_api_tokens_dir() -> PathBuf {
    get_base_dir().join("tokens")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = KineticConfig::default();
        assert_eq!(config.daemon.api_port, ports::API_DAEMON);
        assert_eq!(config.network.daemon_port, ports::P2P_DAEMON);
        assert!(config.network.enable_mdns);
        assert!(config.daemon.enable_dns);
    }

    #[test]
    fn test_bundled_network_json_sync() {
        let root_json_path = PathBuf::from("../network.json");
        let bundled_json_path = PathBuf::from("default_network.json");

        if root_json_path.exists() && bundled_json_path.exists() {
            let root_content = fs::read_to_string(&root_json_path).expect("Failed to read root network.json");
            let bundled_content = fs::read_to_string(&bundled_json_path).expect("Failed to read bundled default_network.json");
            
            assert_eq!(
                root_content, bundled_content,
                "The bundled default_network.json in kinetic-core must perfectly match the root network.json!"
            );
        }
    }
}
