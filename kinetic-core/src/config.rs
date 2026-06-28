use std::fs;
use std::path::PathBuf;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KineticConfig {
    pub daemon: DaemonConfig,
    pub network: P2pConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonConfig {
    pub api_port: u16,
    pub dns_port: u16,
    #[serde(default = "default_proxy_port")]
    pub proxy_port: u16,
    #[serde(default = "default_backend_port")]
    pub backend_port: u16,
    pub storage_dir: PathBuf,
    #[serde(default = "default_network_mode")]
    pub network_mode: String,
}

fn default_network_mode() -> String {
    "FullNode".to_string()
}

fn default_proxy_port() -> u16 {
    5463
}

fn default_backend_port() -> u16 {
    80
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct P2pConfig {
    pub p2p_port: u16,
    pub bootstrap_nodes: Vec<String>,
    #[serde(default)]
    pub seed_domains: Vec<String>,
    #[serde(default)]
    pub enable_mdns: bool,
}

impl Default for KineticConfig {
    fn default() -> Self {
        let storage_dir = dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("kinetic")
            .join("db");

        Self {
            daemon: DaemonConfig {
                api_port: 16002,
                dns_port: 53,
                proxy_port: 5463,
                backend_port: 80,
                storage_dir,
                network_mode: "FullNode".to_string(),
            },
            network: P2pConfig {
                p2p_port: 6070,
                bootstrap_nodes: vec![
                    // Using IP based bootnodes as fallback
                    "/ip4/18.209.46.127/tcp/6070".to_string(),
                    "/ip4/35.172.227.109/tcp/6070".to_string(),
                    "/ip4/52.87.221.199/tcp/6070".to_string(),
                ],
                seed_domains: vec![
                    "seed.saifmukhtar.dev".to_string(),
                ],
                enable_mdns: true,
            },
        }
    }
}

impl KineticConfig {
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
                    tracing::warn!("Failed to parse config.toml: {}. Using defaults.", e);
                    Self::default()
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
            let _ = fs::create_dir_all(parent);
        }
        
        let toml_str = toml::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        fs::write(&config_path, toml_str)
    }
}

/// A globally secure check for Dev Mode. 
/// It mathematically guarantees that Dev Mode cannot be activated in release builds.
pub fn is_dev_mode() -> bool {
    cfg!(debug_assertions) && std::env::var("KINETIC_DEV_MODE").is_ok()
}

/// Returns the path to the directory where local zone JSON files are stored.
pub fn get_zones_dir() -> PathBuf {
    get_base_dir().join("zones")
}

/// Returns the base kinetic directory
pub fn get_base_dir() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("kinetic")
}

/// Returns the path to the API secret token used for local CLI authentication.
pub fn get_api_token_path() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("kinetic")
        .join("api.token")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = KineticConfig::default();
        assert_eq!(config.daemon.api_port, 16002);
        assert_eq!(config.network.p2p_port, 6070);
        assert!(config.network.enable_mdns);
    }
}
