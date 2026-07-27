//! Error types for the kinetic-pac (Proxy Auto-Configuration) daemon.

use thiserror::Error;

/// Defines errors that can occur during OS-level proxy configuration.
#[derive(Error, Debug)]
pub enum PacError {
    /// An IO error occurred while reading or writing PAC state/lock files.
    #[error("IO Error: {0}")]
    Io(#[from] std::io::Error),

    /// An error occurred while serializing or deserializing the saved proxy state.
    #[error("Serialization Error: {0}")]
    Serde(#[from] serde_json::Error),

    /// A system command (like `gsettings`, `networksetup`, or registry manipulation) failed.
    #[error("Command failed: {0}")]
    Command(String),
}
