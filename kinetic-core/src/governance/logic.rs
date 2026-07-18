use ed25519_dalek::VerifyingKey;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

use super::types::{GovernanceEffect, GovernanceState, Hash256, SignedGovernanceMessage};
use crate::constants::{ACTIVE_WINDOW_SECONDS, GUARD_PUBLIC_KEY_HEX, ROOT_PUBLIC_KEY_HEX};
use crate::error::GovernanceError;

/// Validates that the static cryptographic keys required for governance have been correctly initialized.
///
/// # Errors
///
/// Returns a `GovernanceError` if keys are missing, still set to placeholders, or have incorrect lengths.
pub fn validate_keys_initialized() -> Result<(), GovernanceError> {
    if crate::config::is_dev_mode() {
        return Ok(());
    }
    if ROOT_PUBLIC_KEY_HEX.contains("REPLACE_ME") {
        return Err(GovernanceError::MissingRootKey);
    }

    let dummy_state = GovernanceState::new(0);
    let _ = dummy_state.get_root_key()?;
    let _ = dummy_state.get_guard_key()?;

    Ok(())
}

impl GovernanceState {
    /// Initializes a new governance state starting in the Founder phase.
    pub fn new(genesis_timestamp_sec: u64) -> Self {
        Self {
            genesis_timestamp_sec,
            mode: crate::governance::types::GovernanceMode::Founder,
            lock_timestamp_sec: None,
            active_council: Vec::new(),
            last_signature_timestamps: HashMap::new(),
            pending_timelocks: HashMap::new(),
            vetoed_hashes: HashSet::new(),
            pending_updates: HashMap::new(),
            partial_proposals: HashMap::new(),
            founder_premium_grants: 0,
            grace_period_start_sec: None,
            dynamic_root_key: None,
            dynamic_guard_key: None,
        }
    }

    /// Computes the SHA-256 hash of a signed governance message based on its canonical byte representation.
    pub fn hash_action(msg: &SignedGovernanceMessage) -> Hash256 {
        let mut hasher = Sha256::new();
        hasher.update(msg.to_canonical_bytes());
        let result = hasher.finalize();
        let mut array = [0u8; 32];
        array.copy_from_slice(&result);
        array
    }

    /// Merges signatures from an incoming message into the existing state's partial proposal for the same action.
    /// Returns the updated message containing the combined signatures.
    pub fn merge_signatures(
        &mut self,
        incoming_msg: &SignedGovernanceMessage,
    ) -> SignedGovernanceMessage {
        let action_hash = Self::hash_action(incoming_msg);

        let mut msg_to_update = if let Some(existing) = self.partial_proposals.get(&action_hash) {
            existing.clone()
        } else {
            incoming_msg.clone()
        };

        let mut changed = false;
        for sig in &incoming_msg.signatures {
            if !msg_to_update.signatures.contains(sig) {
                msg_to_update.signatures.push(*sig);
                changed = true;
            }
        }

        if changed || !self.partial_proposals.contains_key(&action_hash) {
            self.partial_proposals
                .insert(action_hash, msg_to_update.clone());
        }

        msg_to_update
    }

    /// Counts the number of active council members within the recent active window.
    pub fn count_active_council(&self, current_time_sec: u64) -> usize {
        self.active_council
            .iter()
            .filter(|key| {
                if let Some(&last_sig_time) = self.last_signature_timestamps.get(key) {
                    current_time_sec.saturating_sub(last_sig_time) <= ACTIVE_WINDOW_SECONDS
                } else {
                    false
                }
            })
            .count()
    }

    /// Retrieves the static root verifying key.
    ///
    /// # Errors
    ///
    /// Returns a `GovernanceError` if the key is missing, invalid, or has the wrong length.
    pub fn get_root_key(&self) -> Result<VerifyingKey, GovernanceError> {
        if let Some(key) = self.dynamic_root_key {
            return Ok(key);
        }
        let bytes =
            hex::decode(ROOT_PUBLIC_KEY_HEX).map_err(|_| GovernanceError::MissingRootKey)?;
        if bytes.len() != 32 {
            return Err(GovernanceError::KeyLengthMismatch);
        }
        VerifyingKey::try_from(bytes.as_slice()).map_err(|_| GovernanceError::KeyLengthMismatch)
    }

    /// Retrieves the static guard verifying key, if configured.
    ///
    /// # Errors
    ///
    /// Returns a `GovernanceError` if the key format is invalid.
    pub fn get_guard_key(&self) -> Result<Option<VerifyingKey>, GovernanceError> {
        if let Some(key) = self.dynamic_guard_key {
            return Ok(Some(key));
        }
        if GUARD_PUBLIC_KEY_HEX.contains("REPLACE_ME") {
            return Ok(None);
        }
        let bytes =
            hex::decode(GUARD_PUBLIC_KEY_HEX).map_err(|_| GovernanceError::MissingGuardKey)?;
        if bytes.len() != 32 {
            return Err(GovernanceError::KeyLengthMismatch);
        }
        let key = VerifyingKey::try_from(bytes.as_slice())
            .map_err(|_| GovernanceError::KeyLengthMismatch)?;
        Ok(Some(key))
    }

    /// Verifies whether a signed governance message meets the quorum and validity rules to be executed.
    ///
    /// # Errors
    ///
    /// Returns a `GovernanceError` if the message is stale, signatures are insufficient, timelocks are not met, or other invariants are violated.
    pub fn verify_action(
        &mut self,
        msg: &SignedGovernanceMessage,
        current_time_sec: u64,
    ) -> Result<Option<GovernanceEffect>, GovernanceError> {
        crate::governance::engine::get_active_engine().verify_action(self, msg, current_time_sec)
    }

    /// Executes a verified governance action, applying its state changes and returning any resulting effects.
    pub fn execute_action(
        &mut self,
        msg: &SignedGovernanceMessage,
        current_time_sec: u64,
        wait_time: Option<u64>,
    ) -> Option<GovernanceEffect> {
        crate::governance::engine::get_active_engine().execute_action(
            self,
            msg,
            current_time_sec,
            wait_time,
        )
    }

    /// Checks for any matured timelocked actions (like OTAs) and returns their corresponding effects.
    pub fn check_timelocks(&mut self, current_time_sec: u64) -> Vec<GovernanceEffect> {
        let mut effects = Vec::new();
        let mut matured_hashes = Vec::new();

        for (hash, (broadcast_time, wait_time, mirrors)) in &self.pending_updates {
            if current_time_sec >= broadcast_time.saturating_add(*wait_time) {
                matured_hashes.push((*hash, mirrors.clone()));
            }
        }

        for (hash, mirrors) in matured_hashes {
            self.pending_updates.remove(&hash);
            effects.push(GovernanceEffect::TriggerOTA {
                manifest_hash: hash,
                mirrors,
            });
        }

        effects
    }
}

/// Processes an incoming governance message, merging its signatures and executing the action if quorum is met.
///
/// # Errors
///
/// Returns a `GovernanceError` if the action fails verification or execution rules.
pub fn process_governance_message(
    state: &mut GovernanceState,
    msg: &SignedGovernanceMessage,
) -> Result<Option<GovernanceEffect>, crate::error::GovernanceError> {
    let current_time_sec = web_time::SystemTime::now()
        .duration_since(web_time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    if current_time_sec.abs_diff(msg.timestamp_sec) > crate::constants::MAX_AGE_SECONDS {
        return Err(crate::error::GovernanceError::StaleProposal);
    }

    let action_bytes = msg.to_canonical_bytes();
    let root_key = state.get_root_key()?;
    let guard_key_opt = state.get_guard_key().unwrap_or(None);

    let mut is_authorized = false;
    use ed25519_dalek::Verifier;
    for sig in &msg.signatures {
        if root_key.verify(&action_bytes, sig).is_ok() {
            is_authorized = true;
            break;
        }
        if let Some(guard) = &guard_key_opt {
            if guard.verify(&action_bytes, sig).is_ok() {
                is_authorized = true;
                break;
            }
        }
        for member in &state.active_council {
            if member.verify(&action_bytes, sig).is_ok() {
                is_authorized = true;
                break;
            }
        }
        if is_authorized {
            break;
        }
    }

    if !is_authorized {
        return Err(crate::error::GovernanceError::InsufficientSignatures);
    }

    state.partial_proposals.retain(|_, p| {
        current_time_sec.abs_diff(p.timestamp_sec) <= crate::constants::MAX_AGE_SECONDS
    });

    let msg_to_update = state.merge_signatures(msg);
    state.verify_action(&msg_to_update, current_time_sec)
}
