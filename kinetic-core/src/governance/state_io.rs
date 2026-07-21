//! Persistence and disk serialization helpers for [`GovernanceState`].
//!
//! Provides atomic Bincode state persistence using temporary file renaming and
//! automatic corrupted-state backup routines.

use super::types::GovernanceState;
use lazy_static::lazy_static;
use std::sync::Mutex;

lazy_static! {
    /// Thread-safe global governance state instance initialized from genesis.
    pub static ref GLOBAL_GOVERNANCE_STATE: Mutex<GovernanceState> =
        Mutex::new(GovernanceState::new(
            crate::constants::KINETIC_GENESIS_TIME
        ));
}

impl GovernanceState {
    /// Saves the governance state to disk atomically using a temporary file.
    ///
    /// # Errors
    ///
    /// Returns an `io::Error` if creating, writing to, or renaming the file fails.
    pub fn save_to_disk(&self, path: &std::path::Path) -> std::io::Result<()> {
        let parent = path.parent().unwrap_or_else(|| std::path::Path::new("."));
        let mut temp_file = tempfile::NamedTempFile::new_in(parent)?;
        bincode::serialize_into(&mut temp_file, self).map_err(std::io::Error::other)?;
        temp_file.persist(path).map_err(|e| e.error)?;
        Ok(())
    }

    /// Loads the governance state from disk.
    /// If the file does not exist, a new state is initialized.
    /// Panics if the state file exists but is corrupted or unreadable.
    pub fn load_from_disk(path: &std::path::Path) -> Self {
        match std::fs::File::open(path) {
            Ok(file) => match bincode::deserialize_from(file) {
                Ok(state) => state,
                Err(e) => {
                    let now = web_time::SystemTime::now()
                        .duration_since(web_time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    let corrupt_path = path.with_extension(format!("corrupt.{}", now));
                    let _ = std::fs::rename(path, &corrupt_path);
                    tracing::error!("CRITICAL: Governance state corrupted: {}. Refusing to start with a reset state.", e);
                    panic!("Governance state at {} is corrupt; manual recovery required (backup at {}).", path.display(), corrupt_path.display());
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Self::new(
                crate::constants::KINETIC_GENESIS_TIME
            ),
            Err(e) => {
                tracing::error!("CRITICAL: Failed to read Governance state file: {}.", e);
                panic!(
                    "Governance state at {} is unreadable; manual recovery required.",
                    path.display()
                );
            }
        }
    }
}
