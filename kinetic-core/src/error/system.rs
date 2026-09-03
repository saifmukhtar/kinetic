//! Operating System execution error types (`KIN-SYS-NNN`).
//!
//! Emitted when the operating system fails to bind termination signals (Ctrl+C, SIGTERM), or encounters OS-level faults.

use kinetic_types::error::Severity;
use thiserror::Error;

/// Error emitted during OS-level system failures.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SystemError {
    // --- Networking (001–002) ---
    /// Failed to bind to a required network port (EADDRINUSE).
    /// The node attempted to bind the HTTP or P2P socket to a port that is already taken.
    /// Stop any conflicting processes or change the port in the configuration.
    #[error("Failed to bind network port: {0}")]
    PortInUse(String),
    /// Failed to hot-swap the libp2p network backend.
    /// The runtime attempted to migrate the network layer (e.g. Quic to TCP) but encountered an OS error.
    /// The node must be fully restarted to recover the network interface.
    #[error("Fatal network backend hot-swap failure: {0}")]
    NetworkHotswapFailed(String),

    // --- Runtime (003) ---
    /// A background daemon or API server exited unexpectedly.
    /// A localized panic or unhandled error occurred in one of the async worker pools.
    /// Check the daemon logs for a stack trace.
    #[error("Background server or runtime crashed: {0}")]
    ServerCrashed(String),

    // --- Identity & Keys (004–005) ---
    /// A required static identity or host key on disk is missing, invalid, or corrupted.
    /// The daemon cannot start without its cryptographic identity.
    /// Restore the keyfile from backup or let the daemon generate a fresh identity.
    #[error("Identity keyfile is missing or corrupted: {0}")]
    IdentityCorrupted(String),
    /// Failed to store credentials in the OS Keychain/Keyring.
    /// The daemon attempted to securely store API tokens but was blocked by the OS.
    /// Ensure dbus/keyring services are running, or fall back to plaintext file storage.
    #[error("Failed to store credentials in OS Keychain: {0}")]
    KeychainStorageFailed(String),

    // --- Disk (006) ---
    /// Failed to persist infrastructure state or config to disk.
    /// The daemon lacks permissions to write to its data directory, or the disk is full.
    /// Ensure the app directory is writable by the daemon's user.
    #[error("Failed to persist system files to disk: {0}")]
    DiskPersistenceFailed(String),

    // --- OS Integration (007–010) ---
    /// Failed to interact with the native OS service manager (systemd, launchd, winsw).
    /// The CLI could not start, stop, or install the Kinetic background service.
    /// Ensure you are running with administrator/root privileges.
    #[error("Native OS service manager error: {0}")]
    ServiceManagerError(String),
    /// The OS environment or filesystem paths are invalid (e.g., non-UTF8 paths, arg parse failures).
    /// The daemon was launched in a broken or highly restrictive terminal environment.
    /// Ensure environment variables like `$HOME` are valid UTF-8 strings.
    #[error("Invalid OS environment or filesystem path: {0}")]
    InvalidOsEnvironment(String),
    /// Failed to drop system privileges (setuid/setgid).
    /// The daemon attempted to drop root privileges for security, but the syscall failed.
    /// Ensure the target unprivileged user exists on the system.
    #[error("Failed to drop system privileges: {0}")]
    PrivilegeDropFailed(String),
    /// Failed to setup OS loopback interface (macOS alias).
    /// The daemon could not bind to the secondary loopback IP required for local proxying.
    /// Ensure `ifconfig lo0 alias` can be run, or reboot the OS.
    #[error("Failed to setup OS loopback interface: {0}")]
    LoopbackSetupFailed(String),

    // --- Concurrency (011) ---
    /// A global concurrency mutex was poisoned during a panic.
    /// A thread crashed while holding a critical global lock, corrupting shared state.
    /// The daemon must be restarted to safely recover.
    #[error("Global concurrency lock poisoned: {0}")]
    MutexPoisoned(String),

    // --- PKI / CA (012–013) ---
    /// Failed to install the Root CA into the OS system trust store.
    /// The node attempted to install the TLS intercept root cert, but was blocked by the OS.
    /// Follow the manual installation instructions in the Kinetic UI, or run as administrator.
    #[error("Failed to install Root CA trust: {0}")]
    TrustInstallationFailed(String),
    /// Local Root CA is expiring or auto-rotation failed.
    /// The node could not generate a new Root CA or clean up the old one from the OS.
    /// Manually delete the `~/.kinetic/certs` folder and restart the daemon.
    #[error("Local Root CA expiring or rotation failed: {0}")]
    CaRotationFailed(String),

    // --- OS Signals (014–015) ---
    /// Failed to bind to the SIGINT (Ctrl+C) keyboard signal.
    /// The OS prevented the daemon from intercepting keyboard interrupts.
    /// The daemon may not shut down gracefully when terminated via terminal.
    #[error("Failed to bind Ctrl+C handler: {0}")]
    SigIntBindingFailed(String),
    /// Failed to bind to the POSIX SIGTERM signal.
    /// The OS prevented the daemon from intercepting standard termination requests.
    /// The daemon may not shut down gracefully during system reboots or service stops.
    #[error("Failed to bind SIGTERM handler: {0}")]
    SigTermBindingFailed(String),
}

impl SystemError {
    /// Stable protocol error code.
    pub fn code(&self) -> &'static str {
        match self {
            // --- Networking ---
            Self::PortInUse(_) => "KIN-SYS-001",
            Self::NetworkHotswapFailed(_) => "KIN-SYS-002",
            // --- Runtime ---
            Self::ServerCrashed(_) => "KIN-SYS-003",
            // --- Identity & Keys ---
            Self::IdentityCorrupted(_) => "KIN-SYS-004",
            Self::KeychainStorageFailed(_) => "KIN-SYS-005",
            // --- Disk ---
            Self::DiskPersistenceFailed(_) => "KIN-SYS-006",
            // --- OS Integration ---
            Self::ServiceManagerError(_) => "KIN-SYS-007",
            Self::InvalidOsEnvironment(_) => "KIN-SYS-008",
            Self::PrivilegeDropFailed(_) => "KIN-SYS-009",
            Self::LoopbackSetupFailed(_) => "KIN-SYS-010",
            // --- Concurrency ---
            Self::MutexPoisoned(_) => "KIN-SYS-011",
            // --- PKI / CA ---
            Self::TrustInstallationFailed(_) => "KIN-SYS-012",
            Self::CaRotationFailed(_) => "KIN-SYS-013",
            // --- OS Signals ---
            Self::SigIntBindingFailed(_) => "KIN-SYS-014",
            Self::SigTermBindingFailed(_) => "KIN-SYS-015",
        }
    }

    /// RFC 7807 type URI for this error.
    pub fn error_type_uri(&self) -> String {
        format!("{}/errors/{}", crate::constants::DOCS_URL, self.code())
    }

    /// Severity level for logging and monitoring.
    pub fn severity(&self) -> Severity {
        match self {
            // Warning — degraded but non-fatal
            Self::PortInUse(_) => Severity::Warning,
            Self::CaRotationFailed(_) => Severity::Warning,
            Self::KeychainStorageFailed(_) => Severity::Warning,
            Self::TrustInstallationFailed(_) => Severity::Warning,
            Self::LoopbackSetupFailed(_) => Severity::Warning,
            Self::SigIntBindingFailed(_) => Severity::Warning,
            Self::SigTermBindingFailed(_) => Severity::Warning,
            // Critical — node cannot safely operate
            Self::NetworkHotswapFailed(_) => Severity::Critical,
            Self::ServerCrashed(_) => Severity::Critical,
            Self::IdentityCorrupted(_) => Severity::Critical,
            Self::DiskPersistenceFailed(_) => Severity::Critical,
            Self::ServiceManagerError(_) => Severity::Critical,
            Self::InvalidOsEnvironment(_) => Severity::Critical,
            Self::PrivilegeDropFailed(_) => Severity::Critical,
            Self::MutexPoisoned(_) => Severity::Critical,
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
            Self::NetworkHotswapFailed(_) => "Failed to hot-swap the networking backend.".to_string(),
            Self::ServerCrashed(_) => "A critical background service crashed.".to_string(),
            Self::IdentityCorrupted(_) => "The cryptographic node identity is corrupted.".to_string(),
            Self::KeychainStorageFailed(_) => "Failed to access the OS Keychain/Keyring.".to_string(),
            Self::DiskPersistenceFailed(_) => "Failed to write configuration to disk.".to_string(),
            Self::ServiceManagerError(_) => "Failed to interact with the OS service manager.".to_string(),
            Self::InvalidOsEnvironment(_) => "The operating system environment is invalid.".to_string(),
            Self::PrivilegeDropFailed(_) => "Failed to securely drop root privileges.".to_string(),
            Self::LoopbackSetupFailed(_) => "Failed to configure the OS loopback network interface.".to_string(),
            Self::MutexPoisoned(_) => "A system deadlock occurred (mutex poisoned).".to_string(),
            Self::TrustInstallationFailed(_) => "Failed to install OS certificate trust.".to_string(),
            Self::CaRotationFailed(_) => "Local Certificate Authority rotation failed.".to_string(),
            Self::SigIntBindingFailed(_) => "Graceful keyboard shutdown is disabled (Ctrl+C listener failed).".to_string(),
            Self::SigTermBindingFailed(_) => "Graceful system shutdown is disabled (SIGTERM listener failed).".to_string(),
        }
    }
}
