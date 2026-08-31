//! Configuration parsing and persistence error types (`KIN-CFG-NNN`).
use super::Severity;
use thiserror::Error;

/// Error type for configuration load, save, and validation failures.
#[derive(Error, Debug)]
pub enum ConfigError {
    /// The daemon failed to create the OS-level directory structure for the configuration files.
    /// The node must ensure its base paths exist before initializing, but the OS rejected the system call.
    /// Check the file permissions for the user running the daemon and ensure the disk is not read-only.
    #[error("Failed to create config directory: {0}")]
    DirectoryCreationFailed(String),

    /// The node attempted to write the configuration to disk, but the TOML serialization engine failed.
    /// This usually indicates a critical structural flaw in the default configuration structs or an unsupported data type.
    /// This is an internal node error; report this bug to the Kinetic developers on GitHub.
    #[error("Failed to serialize config: {0}")]
    SerializationFailed(String),

    /// The configuration file could not be written to disk.
    /// The file handle could not be opened for writing, or the system call failed.
    /// Ensure the disk is not full and the daemon has write permissions to the config directory.
    #[error("Failed to write config file: {0}")]
    WriteFailed(String),

    /// The `kinetic.toml` file exists but contains invalid TOML syntax or structural errors.
    /// The node refuses to start with an invalid config rather than failing-open with missing or default parameters.
    /// Review the accompanying error string to find the syntax error or missing field in your config file.
    #[error("Failed to parse config.toml: {0}")]
    ParseFailed(String),

    /// The `kinetic.toml` file exists but could not be read from disk.
    /// The daemon lacks read permissions for the file, or the file was deleted concurrently.
    /// Fix the OS-level file permissions to ensure the daemon user can read the config file.
    #[error("Failed to read config.toml: {0}")]
    ReadFailed(String),

    /// The daemon detected that two or more internal services are trying to bind to the same TCP port.
    /// A misconfigured node will fail to bind its sockets at startup if ports conflict, breaking routing.
    /// Update `kinetic.toml` to ensure all TCP ports (api, proxy, p2p, backend) are entirely unique.
    #[error("TCP port collision detected in config.toml")]
    TcpPortCollision,

    /// The daemon detected that two or more internal services are trying to bind to the same UDP port.
    /// A misconfigured node will fail to bind its sockets at startup if ports conflict, dropping packets.
    /// Update `kinetic.toml` to ensure all UDP ports (nrs, quic) are entirely unique.
    #[error("UDP port collision detected in config.toml")]
    UdpPortCollision,

    /// The `backend_port` in the configuration is set to a port already used by an internal daemon service.
    /// This must be strictly blocked to prevent infinite SSRF loops if the proxy attempts to route traffic back into its own API.
    /// Assign a unique, unused port to your upstream backend application in `kinetic.toml`.
    #[error("backend_port conflicts with an internal daemon port")]
    BackendPortCollision,

    /// A secondary fatal warning paired with `KIN-CFG-008` port collisions.
    /// Leaving this misconfigured exposes the node to infinite routing loops and localized SSRF proxy exploits.
    /// Resolve the port collision immediately before starting the node.
    #[error("SSRF loop risk detected in backend_port")]
    BackendPortSsrfRisk,

    /// A REST API request attempted to update the daemon configuration with invalid data.
    /// The submitted JSON payload failed schema validation (e.g., trying to set a port to a negative number).
    /// Review the accompanying API error response to correct your configuration payload.
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
