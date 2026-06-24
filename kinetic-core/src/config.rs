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
    pub storage_dir: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct P2pConfig {
    pub p2p_port: u16,
    pub bootstrap_nodes: Vec<String>,
}

impl Default for KineticConfig {
    fn default() -> Self {
        let storage_dir = dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("kinetic")
            .join("db");

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
                dirs::config_dir()
                    .unwrap_or_else(|| PathBuf::from("."))
                    .join("kinetic")
                    .join("config.toml")
            });

        let mut config = if let Ok(config_str) = fs::read_to_string(&config_path) {
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

        // Phase 5.3: Bootstrap Node DNS-Based Discovery Fallback
        use hickory_resolver::Resolver;
        use hickory_resolver::config::*;
        if let Ok(resolver) = Resolver::new(ResolverConfig::default(), ResolverOpts::default()) {
            if let Ok(txt_lookup) = resolver.txt_lookup("_kinetic-bootstrap.kin.network.") {
                for txt in txt_lookup.iter() {
                    if let Some(txt_str) = txt.txt_data().first() {
                        if let Ok(addr_str) = std::str::from_utf8(txt_str) {
                            if !config.network.bootstrap_nodes.contains(&addr_str.to_string()) {
                                tracing::info!("Discovered dynamic bootstrap node from DNS: {}", addr_str);
                                config.network.bootstrap_nodes.push(addr_str.to_string());
                            }
                        }
                    }
                }
            }
        }

        config
    }
}
