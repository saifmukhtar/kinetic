//! Operating System execution error types (`KIN-SYS-NNN`).
//!
//! Emitted when the operating system fails to bind termination signals (Ctrl+C, SIGTERM), or encounters OS-level faults.

use kinetic_types::error::Severity;
use thiserror::Error;

/// Error emitted during OS-level system failures.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SystemError {
    /// Failed to bind to a required network port (EADDRINUSE).
    #[error("Failed to bind network port: {0}")]
    PortInUse(String),
    /// A background daemon or API server exited unexpectedly.
    #[error("Background server or runtime crashed: {0}")]
    ServerCrashed(String),
    /// Failed to install the Root CA into the OS system trust store.
    #[error("Failed to install Root CA trust: {0}")]
    TrustInstallationFailed(String),
    /// A global concurrency mutex was poisoned during a panic.
    #[error("Global concurrency lock poisoned: {0}")]
    MutexPoisoned(String),
    /// A required static identity or host key on disk is missing, invalid, or corrupted.
    #[error("Identity keyfile is missing or corrupted: {0}")]
    IdentityCorrupted(String),
    /// Failed to persist infrastructure state or config to disk.
    #[error("Failed to persist system files to disk: {0}")]
    DiskPersistenceFailed(String),
    /// Failed to interact with the native OS service manager (systemd, launchd, winsw).
    #[error("Native OS service manager error: {0}")]
    ServiceManagerError(String),
    /// The OS environment or filesystem paths are invalid (e.g., non-UTF8 paths, arg parse failures).
    #[error("Invalid OS environment or filesystem path: {0}")]
    InvalidOsEnvironment(String),
    /// Failed to hot-swap the libp2p network backend.
    #[error("Fatal network backend hot-swap failure: {0}")]
    NetworkHotswapFailed(String),
    /// Failed to drop system privileges (setuid/setgid).
    #[error("Failed to drop system privileges: {0}")]
    PrivilegeDropFailed(String),
    /// Root CA rotation issues.
    #[error("Local Root CA expiring or rotation failed: {0}")]
    CaRotationFailed(String),
    /// Failed to store credentials in the OS Keychain/Keyring.
    #[error("Failed to store credentials in OS Keychain: {0}")]
    KeychainStorageFailed(String),
    /// Failed to setup OS loopback interface (macOS alias).
    #[error("Failed to setup OS loopback interface: {0}")]
    LoopbackSetupFailed(String),
    /// Failed to bind to the SIGINT (Ctrl+C) keyboard signal.
    #[error("Failed to bind Ctrl+C handler: {0}")]
    SigIntBindingFailed(String),
    /// Failed to bind to the POSIX SIGTERM signal.
    #[error("Failed to bind SIGTERM handler: {0}")]
    SigTermBindingFailed(String),
}

impl SystemError {
    /// Stable protocol error code.
    pub fn code(&self) -> &'static str {
        match self {
            Self::PortInUse(_) => "KIN-SYS-001",
            Self::ServerCrashed(_) => "KIN-SYS-002",
            Self::TrustInstallationFailed(_) => "KIN-SYS-003",
            Self::MutexPoisoned(_) => "KIN-SYS-004",
            Self::IdentityCorrupted(_) => "KIN-SYS-005",
            Self::DiskPersistenceFailed(_) => "KIN-SYS-006",
            Self::ServiceManagerError(_) => "KIN-SYS-007",
            Self::InvalidOsEnvironment(_) => "KIN-SYS-008",
            Self::NetworkHotswapFailed(_) => "KIN-SYS-010",
            Self::PrivilegeDropFailed(_) => "KIN-SYS-012",
            Self::CaRotationFailed(_) => "KIN-SYS-065",
            Self::KeychainStorageFailed(_) => "KIN-SYS-066",
            Self::LoopbackSetupFailed(_) => "KIN-SYS-082",
            Self::SigIntBindingFailed(_) => "KIN-SYS-098",
            Self::SigTermBindingFailed(_) => "KIN-SYS-099",
        }
    }

    /// RFC 7807 type URI for this error.
    pub fn error_type_uri(&self) -> String {
        format!("{}/errors/{}", crate::constants::DOCS_URL, self.code())
    }

    /// Severity level for logging and monitoring.
    pub fn severity(&self) -> Severity {
        match self {
            Self::SigIntBindingFailed(_) | Self::SigTermBindingFailed(_) => Severity::Warning,
            Self::CaRotationFailed(_) | Self::LoopbackSetupFailed(_) => Severity::Warning,
            Self::TrustInstallationFailed(_) | Self::KeychainStorageFailed(_) => Severity::Warning,
            Self::PortInUse(_) | Self::DiskPersistenceFailed(_) => Severity::Error,
            Self::ServerCrashed(_) | Self::MutexPoisoned(_) => Severity::Critical,
            Self::IdentityCorrupted(_) | Self::ServiceManagerError(_) => Severity::Critical,
            Self::InvalidOsEnvironment(_) | Self::PrivilegeDropFailed(_) => Severity::Critical,
            Self::NetworkHotswapFailed(_) => Severity::Critical,
        }
    }

    /// Whether the client should offer a retry action.
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::PortInUse(_) | Self::NetworkHotswapFailed(_))
    }

    /// Returns the user-facing message.
    pub fn user_message(&self) -> String {
        match self {
            Self::PortInUse(_) => "A required network port is already in use.".to_string(),
            Self::ServerCrashed(_) => "A critical background service crashed.".to_string(),
            Self::TrustInstallationFailed(_) => "Failed to install OS certificate trust.".to_string(),
            Self::MutexPoisoned(_) => "A system deadlock occurred (mutex poisoned).".to_string(),
            Self::IdentityCorrupted(_) => "The cryptographic node identity is corrupted.".to_string(),
            Self::DiskPersistenceFailed(_) => "Failed to write configuration to disk.".to_string(),
            Self::ServiceManagerError(_) => "Failed to interact with the OS service manager.".to_string(),
            Self::InvalidOsEnvironment(_) => "The operating system environment is invalid.".to_string(),
            Self::NetworkHotswapFailed(_) => "Failed to hot-swap the networking backend.".to_string(),
            Self::PrivilegeDropFailed(_) => "Failed to securely drop root privileges.".to_string(),
            Self::CaRotationFailed(_) => "Local Certificate Authority rotation failed.".to_string(),
            Self::KeychainStorageFailed(_) => "Failed to access the OS Keychain/Keyring.".to_string(),
            Self::LoopbackSetupFailed(_) => "Failed to configure the OS loopback network interface.".to_string(),
            Self::SigIntBindingFailed(_) => "Graceful keyboard shutdown is disabled (Ctrl+C listener failed).".to_string(),
            Self::SigTermBindingFailed(_) => "Graceful system shutdown is disabled (SIGTERM listener failed).".to_string(),
        }
    }
}
