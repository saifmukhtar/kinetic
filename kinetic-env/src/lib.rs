//! Kinetic Environment SDK
//!
//! A lightweight crate providing the runtime identity and local file paths 
//! for the Kinetic network. Used by external tools, desktop GUIs, and CLIs 
//! to dynamically resolve where the local node's data is stored without 
//! importing the heavy `kinetic-core` consensus codebase.

use std::path::PathBuf;

// Include the compile-time generated constants based on `network.json`.
include!(concat!(env!("OUT_DIR"), "/env_constants.rs"));

/// The default port for the local HTTP API (so tools know where to fetch data)
pub const DEFAULT_API_PORT: u16 = 1420;

/// The default port for the local DNS/Proxy resolver
pub const DEFAULT_PROXY_PORT: u16 = 8080;

/// The default port for the PAC server
pub const DEFAULT_PAC_PORT: u16 = 8081;

/// Returns the base directory where the local Kinetic node stores its data.
/// 
/// Resolution:
/// - Linux: `~/.local/share/<nsp>-<salt_prefix>/`
/// - Windows: `%APPDATA%/<nsp>-<salt_prefix>/`
/// - macOS: `~/Library/Application Support/<nsp>-<salt_prefix>/`
pub fn get_base_dir() -> PathBuf {
    let mut path = dirs::data_local_dir().expect("Could not find local data directory");
    path.push(format!("{}-{}", NSP, SALT_PREFIX));
    path
}

/// Returns the file path of the master ed25519 identity key.
pub fn get_identity_key_path() -> PathBuf {
    get_base_dir().join("identity.key")
}

/// Returns the file path of the daemon configuration file.
pub fn get_config_path() -> PathBuf {
    get_base_dir().join("config.toml")
}

/// Returns the directory where the RocksDB/Sled data zone is stored.
pub fn get_db_dir() -> PathBuf {
    get_base_dir().join("data")
}
