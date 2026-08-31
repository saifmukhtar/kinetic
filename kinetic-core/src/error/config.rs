//! Configuration parsing and persistence error types (`KIN-CFG-NNN`).
use super::Severity;
use thiserror::Error;

/// Error type for configuration load, save, and validation failures.
#[derive(Error, Debug)]
pub enum ConfigError {
    /// The daemon failed to create the OS-level directory structure for the configuration files (e.g., `base_dir/networks/nsp-salt_id/`).
    /// Check the file permissions for the user running the daemon.
    #[error("Failed to create config directory: {0}")]
    DirectoryCreationFailed(String),

    /// The node attempted to write the default configuration, but the TOML serialization engine failed.
    /// This indicates a critical structural flaw in the default config structs.
    #[error("Failed to serialize config: {0}")]
    SerializationFailed(String),

    /// The configuration file could not be written to disk.
    /// Ensure the disk is not full and the daemon has write permissions to the config directory.
    #[error("Failed to write config file: {0}")]
    WriteFailed(String),

    /// The `config.toml` file exists but contains invalid TOML syntax or structural errors.
    /// The node will refuse to start rather than failing-open with missing parameters.
    #[error("Failed to parse config.toml: {0}")]
    ParseFailed(String),

    /// The `config.toml` file exists but could not be read from disk (e.g., permission denied).
    #[error("Failed to read config.toml: {0}")]
    ReadFailed(String),

    /// The daemon detected that two or more internal services are trying to bind to the same TCP port.
    /// Update `config.toml` to ensure all TCP ports (api, proxy, p2p, backend) are unique.
    #[error("TCP port collision detected in config.toml")]
    TcpPortCollision,

    /// The daemon detected that two or more internal services are trying to bind to the same UDP port.
    /// Update `config.toml` to ensure all UDP ports (nrs, atlas, quic) are unique.
    #[error("UDP port collision detected in config.toml")]
    UdpPortCollision,

    /// The `backend_port` in the configuration is set to a port already used by the daemon.
    /// This must be blocked to prevent infinite SSRF loops if the proxy tries to hit itself.
    #[error("backend_port conflicts with an internal daemon port")]
    BackendPortCollision,

    /// A secondary fatal warning paired with KIN-CFG-008.
    /// Leaving this misconfigured opens the node to infinite loops and SSRF proxy exploits.
    #[error("SSRF loop risk detected in backend_port")]
    BackendPortSsrfRisk,

    /// A REST API request attempted to update the daemon configuration with invalid data.
    #[error("Invalid configuration payload provided to the API")]
    InvalidApiUpdate(String),
}

impl ConfigError {
    /// Stable protocol error code.
    pub fn code(&self) -> &'static str {
        match self {
            Self::DirectoryCreationFailed(_) => "KIN-CFG-001",
            Self::SerializationFailed(_) => "KIN-CFG-002",
            Self::WriteFailed(_) => "KIN-CFG-003",
            Self::ParseFailed(_) => "KIN-CFG-004",
            Self::ReadFailed(_) => "KIN-CFG-005",
            Self::TcpPortCollision => "KIN-CFG-006",
            Self::UdpPortCollision => "KIN-CFG-007",
            Self::BackendPortCollision => "KIN-CFG-008",
            Self::BackendPortSsrfRisk => "KIN-CFG-009",
            Self::InvalidApiUpdate(_) => "KIN-CFG-010",
        }
    }

    /// RFC 7807 type URI for this error.
    pub fn error_type_uri(&self) -> String {
        format!("{}/errors/{}", crate::constants::DOCS_URL, self.code())
    }

    /// Severity level for logging and monitoring.
    pub fn severity(&self) -> Severity {
        Severity::Error
    }
}
