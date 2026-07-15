use super::types::GovernanceState;
use lazy_static::lazy_static;
use std::sync::Mutex;

lazy_static! {
    pub static ref GLOBAL_GOVERNANCE_STATE: Mutex<GovernanceState> =
        Mutex::new(GovernanceState::new(
            web_time::SystemTime::now()
                .duration_since(web_time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        ));
}

impl GovernanceState {
    /// Saves the governance state to disk atomically using a temporary file.
    ///
    /// # Errors
    ///
    /// Returns an `io::Error` if creating, writing to, or renaming the file fails.
    pub fn save_to_disk(&self, path: &std::path::Path) -> std::io::Result<()> {
        let temp_path = path.with_extension("tmp");
        let file = std::fs::File::create(&temp_path)?;
        bincode::serialize_into(file, self).map_err(std::io::Error::other)?;
        std::fs::rename(temp_path, path)?;
        Ok(())
    }

    /// Loads the governance state from disk.
    /// If the file does not exist, a new state is initialized.
    /// Panics if the state file exists but is corrupted or unreadable.
    pub fn load_from_disk(path: &std::path::Path) -> Self {
        match std::fs::File::open(path) {
            Ok(file) => match bincode::deserialize_from(file) {
                Ok(state) => state,
                Err(e) => panic!(
                    "CRITICAL: Governance state file is corrupted: {}. Refusing to start.",
                    e
                ),
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Self::new(
                web_time::SystemTime::now()
                    .duration_since(web_time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            ),
            Err(e) => panic!("CRITICAL: Failed to read Governance state file: {}", e),
        }
    }
}
