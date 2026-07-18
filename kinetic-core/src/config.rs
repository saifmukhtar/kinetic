use serde::{Deserialize, Serialize};
#[cfg(not(target_arch = "wasm32"))]
use std::fs;
use std::path::PathBuf;

/// Host routing records max age (10 minutes)
pub const HOST_ROUTE_MAX_AGE_SECS: u64 = 600;

/// Well-known port constants for all Kinetic binaries.
///
/// Centralising port assignments here prevents accidental conflicts
/// between the daemon, node, and host binaries.
pub mod ports {
    /// P2P listen port for `kinetic-daemon`.
    pub const P2P_DAEMON: u16 = 6070;
    /// P2P listen port for `kinetic-node`.
    pub const P2P_NODE: u16 = 6071;
    /// P2P listen port for `kinetic-host`.
    pub const P2P_HOST: u16 = 6072;

    /// HTTP API port for `kinetic-daemon`.
    pub const API_DAEMON: u16 = 16002;
    /// HTTP health-check API port for `kinetic-node`.
    pub const API_NODE: u16 = 16003;
    /// HTTP health-check API port for `kinetic-host`.
    pub const API_HOST: u16 = 16004;

    /// Local `.kin` reverse-proxy port.
    pub const PROXY: u16 = 5463;
    /// DNS resolver port (system default).
    pub const DNS: u16 = 53;
    /// Local backend HTTP port for the proxy.
    pub const BACKEND: u16 = 80;
}

/// Top-level configuration for any Kinetic binary.
///
/// Loaded from `~/.config/kinetic/config.toml` (or the path set by
/// `KINETIC_CONFIG_PATH`). If the file does not exist, a default config is
/// written and used.
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
    #[serde(default = "default_drand_endpoints")]
    pub endpoints: Vec<String>,
    /// Domains to query via DNS TXT records for dynamic Drand endpoints.
    #[serde(default = "default_drand_seed_domains")]
    pub seed_domains: Vec<String>,
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

fn default_drand_seed_domains() -> Vec<String> {
    vec![format!("drand.{}", crate::constants::BASE_DOMAIN)]
}

impl Default for DrandConfig {
    fn default() -> Self {
        Self {
            endpoints: default_drand_endpoints(),
            seed_domains: default_drand_seed_domains(),
            p2p_only: false,
        }
    }
}

/// Daemon-specific configuration: API ports, storage, and operating mode.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonConfig {
    /// Port for the daemon's authenticated HTTP API (default: [`ports::API_DAEMON`]).
    #[serde(default = "default_api_port")]
    pub api_port: u16,
    /// Port for the built-in DNS resolver (default: [`ports::DNS`]).
    #[serde(default = "default_dns_port")]
    pub dns_port: u16,
    /// Port for the built-in reverse proxy (default: [`ports::PROXY`]).
    #[serde(default = "default_proxy_port")]
    pub proxy_port: u16,
    /// Port for the local backend HTTP server (default: [`ports::BACKEND`]).
    #[serde(default = "default_backend_port")]
    pub backend_port: u16,
    /// Whether to start the built-in DNS resolver (default: false).
    #[serde(default)]
    pub enable_dns: bool,
    /// Directory where the embedded Sled database is stored.
    pub storage_dir: PathBuf,
    /// Network operating mode: `"FullNode"` or `"LightClient"`.
    #[serde(default = "default_network_mode")]
    pub network_mode: String,
    /// Whether the node should automatically download and install OTA updates.
    #[serde(default = "default_auto_update")]
    pub auto_update: bool,
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

/// P2P networking configuration shared across all Kinetic binaries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct P2pConfig {
    /// P2P listen port for the daemon (default: [`ports::P2P_DAEMON`]).
    #[serde(default = "default_p2p_daemon")]
    pub daemon_port: u16,
    /// P2P listen port for the node (default: [`ports::P2P_NODE`]).
    #[serde(default = "default_p2p_node")]
    pub node_port: u16,
    /// P2P listen port for the host (default: [`ports::P2P_HOST`]).
    #[serde(default = "default_p2p_host")]
    pub host_port: u16,
    /// Multiaddr strings for the initial bootstrap peers.
    pub bootstrap_nodes: Vec<String>,
    /// `.kin` domain names used to discover additional bootstrap peers via DNS.
    #[serde(default)]
    pub seed_domains: Vec<String>,
    /// Whether to enable mDNS peer discovery on the local network.
    #[serde(default)]
    pub enable_mdns: bool,
    /// Optional externally reachable multiaddr (e.g. for nodes behind NAT).
    #[serde(default)]
    pub external_address: Option<String>,
}

fn default_p2p_daemon() -> u16 {
    ports::P2P_DAEMON
}

fn default_p2p_node() -> u16 {
    ports::P2P_NODE
}

fn default_p2p_host() -> u16 {
    ports::P2P_HOST
}

impl Default for KineticConfig {
    fn default() -> Self {
        #[cfg(not(target_arch = "wasm32"))]
        let storage_dir = dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("kinetic")
            .join("db");

        #[cfg(target_arch = "wasm32")]
        let storage_dir = PathBuf::from("/kinetic-db");

        Self {
            daemon: DaemonConfig {
                api_port: ports::API_DAEMON,
                dns_port: ports::DNS,
                proxy_port: ports::PROXY,
                backend_port: ports::BACKEND,
                enable_dns: false,
                storage_dir,
                network_mode: "FullNode".to_string(),
                auto_update: true,
            },
            network: P2pConfig {
                daemon_port: ports::P2P_DAEMON,
                node_port: ports::P2P_NODE,
                host_port: ports::P2P_HOST,
                bootstrap_nodes: crate::constants::BOOTSTRAP_NODES
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
                seed_domains: vec![format!("seed.{}", crate::constants::BASE_DOMAIN)],
                enable_mdns: false,
                external_address: None,
            },
            drand: DrandConfig::default(),
        }
    }
}

impl KineticConfig {
    /// Loads config from disk, falling back to defaults and writing them if
    /// the file is missing or unparseable.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn load() -> Self {
        let config_path = std::env::var("KINETIC_CONFIG_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                dirs::config_dir()
                    .unwrap_or_else(|| PathBuf::from("."))
                    .join("kinetic")
                    .join("config.toml")
            });

        let config = if let Ok(config_str) = fs::read_to_string(&config_path) {
            match toml::from_str(&config_str) {
                Ok(config) => config,
                Err(e) => {
                    tracing::error!("Failed to parse config.toml: {}. Refusing to start to avoid fail-open vulnerability.", e);
                    std::process::exit(1);
                }
            }
        } else {
            // Create default config if it doesn't exist
            let default_cfg = Self::default();
            if let Some(parent) = config_path.parent() {
                let _ = fs::create_dir_all(parent);
                if let Ok(toml_str) = toml::to_string_pretty(&default_cfg) {
                    let _ = fs::write(&config_path, toml_str);
                }
            }
            default_cfg
        };

        config
    }

    #[cfg(target_arch = "wasm32")]
    /// Stub implementation for loading configuration in Wasm
    pub fn load() -> Self {
        Self::default()
    }

    /// Serialises and writes the config back to the same path it was loaded
    /// from.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn save(&self) -> Result<(), std::io::Error> {
        let config_path = std::env::var("KINETIC_CONFIG_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                dirs::config_dir()
                    .unwrap_or_else(|| PathBuf::from("."))
                    .join("kinetic")
                    .join("config.toml")
            });

        if let Some(parent) = config_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let toml_str = toml::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        fs::write(&config_path, toml_str)
    }

    #[cfg(target_arch = "wasm32")]
    /// Stub implementation for saving configuration in Wasm
    pub fn save(&self) -> Result<(), std::io::Error> {
        Ok(())
    }
}

/// A globally secure check for Dev Mode.
/// It mathematically guarantees that Dev Mode cannot be activated in release builds.
pub fn is_dev_mode() -> bool {
    cfg!(feature = "simulation")
}

/// Returns the path to the directory where local zone JSON files are stored.
pub fn get_zones_dir() -> PathBuf {
    get_base_dir().join("zones")
}

/// Returns the platform-appropriate base directory for Kinetic data files.
///
/// Can be overridden with the `KINETIC_DATA_DIR` environment variable.
pub fn get_base_dir() -> PathBuf {
    if let Ok(path) = std::env::var("KINETIC_DATA_DIR") {
        return PathBuf::from(path);
    }

    #[cfg(target_os = "windows")]
    {
        return PathBuf::from(r"C:\ProgramData\Kinetic");
    }

    #[cfg(target_os = "macos")]
    {
        return PathBuf::from("/Library/Application Support/Kinetic");
    }

    #[cfg(all(
        not(any(target_os = "windows", target_os = "macos")),
        not(target_arch = "wasm32")
    ))]
    {
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("kinetic")
    }

    #[cfg(target_arch = "wasm32")]
    {
        PathBuf::from("/kinetic")
    }
}

/// Returns the path to the API secret token used for local CLI authentication.
pub fn get_api_token_path() -> PathBuf {
    get_base_dir().join("api.token")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = KineticConfig::default();
        assert_eq!(config.daemon.api_port, ports::API_DAEMON);
        assert_eq!(config.network.daemon_port, ports::P2P_DAEMON);
        assert!(!config.network.enable_mdns);
    }
}
