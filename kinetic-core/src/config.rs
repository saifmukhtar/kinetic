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
    /// Default UDP NRS resolver port for native OS queries (53).
    pub const NRS: u16 = 53;
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
    /// Drand HTTP endpoints to query for Quicknet kyns.
    #[serde(default = "default_drand_endpoints")]
    pub endpoints: Vec<String>,
    /// Domains to query via DNS TXT records for dynamic Drand endpoints.
    #[serde(default = "default_drand_seed_domain")]
    pub drand_domain: Vec<String>,
    /// If true, the node will only listen to P2P gossipsub for Drand kyns
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
    #[serde(default = "local_bind_ip")]
    pub bind_ip: String,
    /// IP address used by the PAC script and the proxy.
    #[serde(default = "default_pac_bind_ip")]
    pub pac_bind_ip: String,
    /// Port for the daemon's authenticated HTTP API (default: [`ports::API_DAEMON`]).
    #[serde(default = "default_api_port")]
    pub api_port: u16,

    /// Port for the built-in DNS resolver (default: [`ports::DNS`]).
    #[serde(default = "default_nrs_port")]
    pub nrs_port: u16,
    /// Port for the built-in HTTP reverse proxy (default: [`ports::PROXY`]).
    #[serde(default = "default_proxy_port")]
    pub proxy_port: u16,
    /// Port for the local backend HTTP server (default: [`ports::BACKEND`]).
    #[serde(default = "default_backend_port")]
    pub backend_port: u16,
    /// Whether to start the built-in UDP DNS resolver on boot (default: `true`).
    #[serde(default = "default_true")]
    pub enable_nrs: bool,
    /// Path to the directory where the embedded storage database is persisted.
    pub storage_dir: PathBuf,
    /// Network operating mode. Supported values: `"FullNode"` (participates in DHT storage & routing)
    /// or `"LightNode"` (queries network without storing records).
    #[serde(default = "default_network_mode")]
    pub network_mode: String,

    /// Port for the PAC (Proxy Auto-Config) server (default: [`ports::PAC`]).
    #[serde(default = "default_pac_port")]
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

fn default_true() -> bool {
    true
}

fn default_network_mode() -> String {
    "FullNode".to_string()
}

fn default_api_port() -> u16 {
    ports::API_DAEMON
}

fn default_nrs_port() -> u16 {
    ports::NRS
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
    #[serde(default = "default_p2p_daemon")]
    pub daemon_port: u16,
    /// P2P listen port for the daemon over QUIC (default: [`ports::P2P_DAEMON`]).
    #[serde(default = "default_p2p_daemon_quic")]
    pub daemon_quic_port: u16,
    /// P2P listen port for the node (default: [`ports::P2P_NODE`]).
    #[serde(default = "default_p2p_node")]
    pub node_port: u16,
    /// P2P listen port for the node over QUIC (default: [`ports::P2P_NODE`]).
    #[serde(default = "default_p2p_node_quic")]
    pub node_quic_port: u16,
    /// P2P listen port for the host (default: [`ports::P2P_HOST`]).
    #[serde(default = "default_p2p_host")]
    pub host_port: u16,
    /// P2P listen port for the host over QUIC (default: [`ports::P2P_HOST`]).
    #[serde(default = "default_p2p_host_quic")]
    pub host_quic_port: u16,
    /// Multiaddr strings for the initial bootstrap peers.
    pub bootstrap_nodes: Vec<String>,
    /// `.kin` domain names used to discover additional bootstrap peers via DNS.
    #[serde(default)]
    pub seed_domain: Vec<String>,
    /// Whether to enable mDNS peer discovery on the local network.
    #[serde(default = "default_true")]
    pub enable_mdns: bool,
    /// Whether to enable UPnP automatic port forwarding.
    #[serde(default = "default_true")]
    pub enable_upnp: bool,
    /// Whether to act as a public Relay Server for NAT-trapped peers.
    #[serde(default = "default_true")]
    pub enable_relay_server: bool,
    /// Optional externally reachable multiaddr (e.g. for nodes behind NAT).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_address: Option<String>,
    /// Send anonymous statistics to map network health.
    /// Enabled by default to ensure an accurate network map, but uses a ghost SessionID for absolute privacy.
    #[serde(default = "default_true")]
    pub enable_anonymous_telemetry: bool,
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

impl Default for KineticConfig {
    fn default() -> Self {
        #[cfg(not(target_arch = "wasm32"))]
        let storage_dir = PathBuf::from("db");

        #[cfg(target_arch = "wasm32")]
        let storage_dir = PathBuf::from("/kinetic-db");

        Self {
            daemon: DaemonConfig {
                bind_ip: crate::constants::LOCAL_BIND_IP.to_string(),
                pac_bind_ip: crate::constants::LOCAL_BIND_IP.to_string(),
                api_port: ports::API_DAEMON,
                nrs_port: ports::NRS,
                proxy_port: ports::PROXY,
                backend_port: ports::BACKEND,
                enable_nrs: true,
                storage_dir,
                network_mode: "FullNode".to_string(),
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
                enable_upnp: true,
                enable_relay_server: true,
                external_address: None,
                enable_anonymous_telemetry: true,
            },
            drand: DrandConfig::default(),
        }
    }
}

/// Defines the operational context loading the configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigContext {
    /// Loaded by a user-facing daemon or CLI tool.
    Daemon,
    /// Loaded by a cloud infrastructure node.
    Node,
}

/// Returns `true` if compile-time simulation mode is enabled (`cfg!(feature = "simulation")`).
///
/// Mathematically guarantees that dev-mode mocks cannot be activated in release builds.
pub fn is_dev_mode() -> bool {
    cfg!(feature = "simulation")
}

impl KineticConfig {
    /// Validates the configuration for internal consistency.
    pub fn validate(&self) {
        let mut tcp_ports = vec![
            self.daemon.api_port,
            self.daemon.proxy_port,
            self.daemon.backend_port,
            self.daemon.pac_port,
            self.network.daemon_port,
            self.network.node_port,
            self.network.host_port,
        ];
        let tcp_len = tcp_ports.len();
        tcp_ports.sort_unstable();
        tcp_ports.dedup();

        if tcp_ports.len() != tcp_len {
            let err = crate::error::ConfigError::TcpPortCollision;
            tracing::error!(error_code = err.code(), "{}", err);
            std::process::exit(1);
        }

        let mut udp_ports = vec![
            self.daemon.nrs_port,
            self.daemon.atlas_port,
            self.network.daemon_quic_port,
            self.network.node_quic_port,
            self.network.host_quic_port,
        ];
        let udp_len = udp_ports.len();
        udp_ports.sort_unstable();
        udp_ports.dedup();

        if udp_ports.len() != udp_len {
            let err = crate::error::ConfigError::UdpPortCollision;
            tracing::error!(error_code = err.code(), "{}", err);
            std::process::exit(1);
        }
    }
}
