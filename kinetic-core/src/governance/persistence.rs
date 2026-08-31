//! Persistence and disk serialization helpers for [`GovernanceState`].
//!
//! Provides atomic Bincode state persistence using temporary file renaming and
//! automatic corrupted-state backup routines.
//!
//! ## Persistence Strategy
//!
//! State is saved via a write-then-rename pattern: the new state is Bincode-serialized
//! into a `tempfile::NamedTempFile` in the same directory as the target file, then
//! atomically renamed into place. This prevents partial writes from corrupting the state.
//!
//! On load, if the state file is Bincode-unreadable, the daemon:
//! 1. Renames the corrupted file to `governance.state.corrupt.{unix_timestamp}` for recovery.
//! 2. **Panics** with a human-readable error requiring manual intervention.
//!
//! This is intentional: a corrupted governance state may indicate an active attack and
//! should never silently reset to a blank state.

use super::types::GovernanceState;
use lazy_static::lazy_static;
use std::sync::Mutex;

lazy_static! {
    /// Thread-safe global governance state instance initialized from genesis.
    pub static ref GLOBAL_GOVERNANCE_STATE: Mutex<GovernanceState> =
        Mutex::new(GovernanceState::new(
            crate::constants::KINETIC_GENESIS_KYN
        ));
}

impl GovernanceState {
    /// Saves the governance state to disk atomically via a temporary file.
    ///
    /// The state is Bincode-serialized into a `tempfile::NamedTempFile` in the same
    /// parent directory as `path`, then atomically renamed into place.
    ///
    /// # Errors
    ///
    /// Returns an `io::Error` if:
    /// - Creating the temp file fails (OS-level permission or disk error).
    /// - Bincode serialization fails (wrapped via `io::Error::other`).
    /// - Renaming the temp file to the target path fails.
    pub fn save_to_disk(&self, path: &std::path::Path) -> std::io::Result<()> {
        let parent = path.parent().unwrap_or_else(|| std::path::Path::new("."));
        let mut temp_file = tempfile::NamedTempFile::new_in(parent)?;
        bincode::serialize_into(&mut temp_file, self).map_err(std::io::Error::other)?;
        temp_file.persist(path).map_err(|e| e.error)?;
        Ok(())
    }

    /// Loads the governance state from disk, or initializes a fresh genesis state if no file exists.
    ///
    /// # Returns
    ///
    /// The deserialized [`GovernanceState`] on success, or a fresh genesis state if the file is absent.
    ///
    /// # Panics
    ///
    /// Panics if the governance state file **exists but is corrupt** (Bincode deserialize fails).
    /// Before panicking, the corrupted file is renamed to `{path}.corrupt.{unix_ts}` for manual recovery.
    /// This is deliberate — a corrupt governance file may indicate tampering and must never
    /// silently reset to a blank genesis state.
    ///
    /// Also panics if the file exists but cannot be opened due to OS-level permission errors.
    pub fn load_from_disk(path: &std::path::Path) -> Self {
        match std::fs::File::open(path) {
            Ok(file) => match bincode::deserialize_from(file) {
                Ok(state) => state,
                Err(e) => {
                    let now = web_time::SystemTime::now()
                        .duration_since(web_time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    let mut new_name = path.file_name().unwrap_or_default().to_os_string();
                    new_name.push(format!(".corrupt.{}", now));
                    let corrupt_path = path.with_file_name(new_name);
                    let _ = std::fs::rename(path, &corrupt_path);
                    let err = crate::error::GovernanceError::StateCorrupted;
                    tracing::error!(
                        error_code = err.code(),
                        "CRITICAL: Governance state corrupted: {}. Refusing to start with a reset state.",
                        e
                    );
                    panic!(
                        "Governance state at {} is corrupt; manual recovery required (backup at {}).",
                        path.display(),
                        corrupt_path.display()
                    );
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Self::new(crate::constants::KINETIC_GENESIS_KYN)
            }
            Err(e) => {
                let err = crate::error::GovernanceError::StateReadFailed;
                tracing::error!(error_code = err.code(), "CRITICAL: Failed to read Governance state file: {}.", e);
                panic!(
                    "Governance state at {} is unreadable; manual recovery required.",
                    path.display()
                );
            }
        }
    }
}
