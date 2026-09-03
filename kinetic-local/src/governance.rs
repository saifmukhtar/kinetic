use kinetic_core::governance::GovernanceState;
use lazy_static::lazy_static;
use std::sync::Mutex;
use std::time::SystemTime;

lazy_static! {
    pub static ref GLOBAL_GOVERNANCE_STATE: Mutex<GovernanceState> =
        Mutex::new(GovernanceState::new(kinetic_core::types::clock::Kyn(
            kinetic_core::constants::KINETIC_GENESIS_KYN
        )));
}

pub fn save_governance_to_disk(
    state: &GovernanceState,
    path: &std::path::Path,
) -> std::io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    let mut temp_file = tempfile::NamedTempFile::new_in(parent)?;
    bincode::serialize_into(&mut temp_file, state).map_err(std::io::Error::other)?;
    temp_file.persist(path).map_err(|e| e.error)?;
    Ok(())
}

pub fn load_governance_from_disk(path: &std::path::Path) -> GovernanceState {
    match std::fs::File::open(path) {
        Ok(file) => match bincode::deserialize_from(file) {
            Ok(state) => state,
            Err(e) => {
                let now = SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let mut new_name = path.file_name().unwrap_or_default().to_os_string();
                new_name.push(format!(".corrupt.{}", now));
                let corrupt_path = path.with_file_name(new_name);
                let _ = std::fs::rename(path, &corrupt_path);
                let err = kinetic_core::error::GovernanceError::StateCorrupted;
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
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => GovernanceState::new(
            kinetic_core::types::clock::Kyn(kinetic_core::constants::KINETIC_GENESIS_KYN),
        ),
        Err(e) => {
            let err = kinetic_core::error::GovernanceError::StateReadFailed;
            tracing::error!(
                error_code = err.code(),
                "CRITICAL: Failed to read Governance state file: {}.",
                e
            );
            panic!(
                "Governance state at {} is unreadable; manual recovery required.",
                path.display()
            );
        }
    }
}
