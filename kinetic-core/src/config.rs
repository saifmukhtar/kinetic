use std::fs;
use std::path::PathBuf;
use serde::{Deserialize, Serialize};
use directories::ProjectDirs;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KineticConfig {
    pub daemon: DaemonConfig,
    pub network: P2pConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonConfig {
    pub api_port: u16,
    pub dns_port: u16,
    pub storage_dir: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct P2pConfig {
    pub p2p_port: u16,
    pub bootstrap_nodes: Vec<String>,
}

impl Default for KineticConfig {
    fn default() -> Self {
        let storage_dir = ProjectDirs::from("com", "kinetic", "kinetic")
            .map(|d| d.data_dir().to_path_buf())
            .unwrap_or_else(|| PathBuf::from("/tmp/kinetic_db"));

        Self {
            daemon: DaemonConfig {
                api_port: 6001,
                dns_port: 53,
                storage_dir,
            },
            network: P2pConfig {
                p2p_port: 6070,
                bootstrap_nodes: vec![
                    "/ip4/54.146.215.204/tcp/6070/p2p/12D3KooWSeNyiZPyr798mE6PAc7Mhh1dikvBv4PEaxp2hxDWuAUD".to_string(),
                    "/ip4/54.82.243.125/tcp/6070/p2p/12D3KooWLdtVq46VggMkHJdtfo9fMrYbiHWmUEm6Cgzhe1vrhbup".to_string(),
                ],
            },
        }
    }
}

impl KineticConfig {
    pub fn load() -> Self {
        let config_path = std::env::var("KINETIC_CONFIG_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                ProjectDirs::from("com", "kinetic", "kinetic")
                    .map(|d| d.config_dir().join("config.toml"))
                    .unwrap_or_else(|| PathBuf::from("/tmp/kinetic_config.toml"))
            });

        if let Ok(config_str) = fs::read_to_string(&config_path) {
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
        }
    }
}
