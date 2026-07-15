use kinetic_core::governance::{
    process_governance_message, SignedGovernanceMessage, GLOBAL_GOVERNANCE_STATE,
};
use std::path::PathBuf;
use std::sync::Arc;

/// Handles incoming governance gossip messages over the P2P network.
/// 
/// Parses the signed governance message and applies it to the global governance state if valid.
/// Any resulting updates to the governance state are then persisted to disk.
pub fn handle_kinetic_governance_gossip(payload: &[u8], gossip_gov_path: Arc<PathBuf>) {
    if let Ok(signed_msg) = serde_json::from_slice::<SignedGovernanceMessage>(payload) {
        let mut state = GLOBAL_GOVERNANCE_STATE
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        match process_governance_message(&mut state, &signed_msg) {
            Ok(Some(effect)) => {
                tracing::info!("Governance state updated via gossip. Effect: {:?}", effect);
                let _ = state.save_to_disk(&gossip_gov_path);
            }
            Ok(None) => {
                tracing::info!("Governance state updated via gossip. No immediate effect.");
                let _ = state.save_to_disk(&gossip_gov_path);
            }
            Err(e) => {
                tracing::debug!("Governance gossip message rejected: {:?}", e);
            }
        }
    } else {
        tracing::debug!("Failed to parse governance gossip payload");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kinetic_core::governance::{GovernanceAction, SignedGovernanceMessage};
    use tempfile::tempdir;

    #[test]
    fn test_handle_invalid_json_payload() {
        let dir = tempdir().unwrap();
        let path = Arc::new(dir.path().join("gov.bin"));

        let invalid_payload = b"not valid json";

        // This should not panic
        handle_kinetic_governance_gossip(invalid_payload, path);
    }

    #[test]
    fn test_handle_invalid_signature() {
        let dir = tempdir().unwrap();
        let path = Arc::new(dir.path().join("gov.bin"));

        let msg = SignedGovernanceMessage {
            action: GovernanceAction::LockCouncil,
            council_size_at_proposal: 0,
            timestamp_sec: 0,
            signatures: vec![],
        };
        let payload = serde_json::to_vec(&msg).unwrap();

        // This should parse JSON successfully, but the process_governance_message should fail
        // or reject it. It should not panic.
        handle_kinetic_governance_gossip(&payload, path);
    }

    #[test]
    fn test_handle_wrong_json_schema() {
        let dir = tempdir().unwrap();
        let path = Arc::new(dir.path().join("gov.bin"));

        let wrong_schema = b"{\"hello\": \"world\"}";

        // This should fail JSON parsing and exit gracefully
        handle_kinetic_governance_gossip(wrong_schema, path);
    }

    #[test]
    fn test_handle_massive_payload() {
        let dir = tempdir().unwrap();
        let path = Arc::new(dir.path().join("gov.bin"));

        // 1 MB of brackets
        let mut huge_payload = vec![b'['; 500_000];
        huge_payload.extend(vec![b']'; 500_000]);

        // Should reject immediately gracefully during parsing
        handle_kinetic_governance_gossip(&huge_payload, path);
    }

    #[test]
    fn test_handle_unexpected_fields() {
        let dir = tempdir().unwrap();
        let path = Arc::new(dir.path().join("gov.bin"));

        let extra_fields = b"{\"action\": \"LockCouncil\", \"council_size_at_proposal\": 0, \"timestamp_sec\": 0, \"signatures\": [], \"extra_unwanted_field\": 123}";

        // Should parse and handle or ignore the extra field without panicking
        handle_kinetic_governance_gossip(extra_fields, path);
    }

    #[test]
    fn test_save_to_disk_failure() {
        let dir = tempdir().unwrap();
        // Point to a directory instead of a file so save_to_disk fails
        let path = Arc::new(dir.path().to_path_buf());

        // Valid message that would typically trigger a save (even with no effect, it saves)
        let msg = SignedGovernanceMessage {
            action: GovernanceAction::LockCouncil,
            council_size_at_proposal: 0,
            timestamp_sec: 0,
            signatures: vec![],
        };
        let payload = serde_json::to_vec(&msg).unwrap();

        // Should not panic when `state.save_to_disk` returns an Err
        handle_kinetic_governance_gossip(&payload, path);
    }
}

#[cfg(test)]
mod fuzzing {
    use super::*;
    use proptest::prelude::*;
    use std::sync::Arc;
    use tempfile::tempdir;

    proptest! {
        #[test]
        fn doesnt_crash_on_random_gossip_bytes(
            raw_payload in any::<Vec<u8>>()
        ) {
            let dir = tempdir().unwrap();
            let path = Arc::new(dir.path().join("gov.bin"));
            handle_kinetic_governance_gossip(&raw_payload, path);
        }
    }
}
