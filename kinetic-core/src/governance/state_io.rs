use std::sync::Mutex;
use lazy_static::lazy_static;
use super::types::GovernanceState;

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
    pub fn save_to_disk(&self, path: &std::path::Path) -> std::io::Result<()> {
        let temp_path = path.with_extension("tmp");
        let file = std::fs::File::create(&temp_path)?;
        bincode::serialize_into(file, self).map_err(std::io::Error::other)?;
        std::fs::rename(temp_path, path)?;
        Ok(())
    }

    pub fn load_from_disk(path: &std::path::Path) -> Self {
        if let Ok(file) = std::fs::File::open(path) {
            if let Ok(state) = bincode::deserialize_from(file) {
                return state;
            }
        }
        Self::new(
            web_time::SystemTime::now()
                .duration_since(web_time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        )
    }
}
