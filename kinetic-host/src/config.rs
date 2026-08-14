use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Persistent configuration for the local backend proxy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostConfig {
    /// The local port where the Web2 server is listening.
    pub backend_port: u16,
    /// The local host address where the Web2 server is listening.
    pub backend_host: String,
}

impl Default for HostConfig {
    fn default() -> Self {
        Self {
            backend_port: 80,
            backend_host: "127.0.0.1".to_string(),
        }
    }
}

impl HostConfig {
    /// Load the configuration from disk, or return the default if it doesn't exist.
    pub fn load_or_default(path: &PathBuf) -> Self {
        if let Ok(bytes) = std::fs::read(path)
            && let Ok(config) = serde_json::from_slice(&bytes)
        {
            return config;
        }
        Self::default()
    }

    /// Save the current configuration to disk.
    pub fn save(&self, path: &PathBuf) -> anyhow::Result<()> {
        let bytes = serde_json::to_vec_pretty(self)?;
        std::fs::write(path, bytes)?;
        Ok(())
    }
}
