//! Core governance state transitions, message signature aggregation, and timelock management.
//!
//! Implements the `GovernanceState` mutating operations that are called by the
//! active [`GovernanceEngine`](crate::traits::GovernanceEngine) after signature verification:
//! - [`GovernanceState::new`] — genesis state initialization
//! - [`GovernanceState::hash_action`] — deterministic SHA-256 action hash derivation
//! - [`GovernanceState::merge_signatures`] — threshold signature aggregation
//! - [`GovernanceState::prune`] — stale proposal garbage collection
//! - Key getters: `get_root_key`, `get_guard_key`, `is_council_member`

use sha2::{Digest, Sha256};
use std::collections::HashMap;

use super::types::{
    GovernanceEffect, GovernanceState, Hash256, PublicKeyBytes, SignedGovernanceMessage,
};
use crate::constants::ROOT_PUBLIC_KEY_HEX;
use crate::error::GovernanceError;

/// Validates that the static cryptographic keys required for governance have been correctly initialized.
///
/// # Errors
///
/// - Returns [`GovernanceError::MissingRootKey`] if the root key hex string is unconfigured or invalid.
/// - Returns [`GovernanceError::MissingRootKey`] if the root key hex string is unconfigured or invalid.
/// - Returns [`GovernanceError::KeyLengthMismatch`] if a public key is not exactly 1,952 bytes.
pub fn validate_keys_initialized() -> Result<(), GovernanceError> {
    if crate::config::is_dev_mode() {
        return Ok(());
    }
    if ROOT_PUBLIC_KEY_HEX.contains("REPLACE_ME") {
        return Err(GovernanceError::MissingRootKey);
    }

    let dummy_state = GovernanceState::new(0);
    let _ = dummy_state.get_root_key()?;

    Ok(())
}

impl GovernanceState {
    /// Initializes a new [`GovernanceState`] at network genesis.
    ///
    /// The state starts in `GovernanceMode::Founder` with an empty council,
    /// no pending updates, and no premium grants.
    ///
    /// # Returns
    ///
    /// A new `GovernanceState` ready for genesis block processing.
    pub fn new(genesis_timestamp_sec: u64) -> Self {
        Self {
            genesis_timestamp_sec,
            active_root_key: None,
            is_halted: false,
            total_paused_rounds: 0,
            pause_history: Vec::new(),
            executed_hashes: HashMap::new(),
        }
    }

    /// Computes the SHA-256 action hash for a signed governance message.
    ///
    /// The hash is derived from `SHA-256(msg.to_canonical_bytes())` and is used as the
    /// stable key for all subsequent state operations (timelock map, partial proposal map).
    ///
    /// # Returns
    ///
    /// A deterministic 32-byte `[u8; 32]` SHA-256 hash of the canonical message bytes.
    pub fn hash_action(msg: &SignedGovernanceMessage) -> Hash256 {
        let mut hasher = Sha256::new();
        hasher.update(msg.to_canonical_bytes());
        let result = hasher.finalize();
        let mut array = [0u8; 32];
        array.copy_from_slice(&result);
        array
    }

    /// Removes expired timelocks and stale partial proposals to prevent unbounded memory growth.
    ///
    /// Items are pruned if they have been executed for more than the network's `MAX_AGE_SECONDS`.
    /// This ensures the in-memory governance state remains bounded even across long-running daemon processes.
    pub fn prune(&mut self, current_time_sec: u64) {
        // Remove executed hashes older than the max age
        self.executed_hashes.retain(|_, exec_time| {
            current_time_sec <= *exec_time + crate::constants::MAX_AGE_SECONDS
        });
    }

    /// Retrieves the static root verifying key.
    ///
    /// # Errors
    ///
    /// Returns a `GovernanceError` if the key is missing, invalid, or has the wrong length.
    pub fn get_root_key(&self) -> Result<PublicKeyBytes, GovernanceError> {
        if let Some(key) = &self.active_root_key {
            return Ok(key.clone());
        }

        let bytes =
            hex::decode(ROOT_PUBLIC_KEY_HEX).map_err(|_| GovernanceError::MissingRootKey)?;
        if bytes.len() != 1952 {
            return Err(GovernanceError::KeyLengthMismatch);
        }
        Ok(bytes)
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
    ) -> Option<GovernanceEffect> {
        crate::governance::engine::get_active_engine().execute_action(self, msg, current_time_sec)
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
        .unwrap_or_default()
        .as_secs();

    state.prune(current_time_sec);

    let action_hash = GovernanceState::hash_action(msg);
    if state.executed_hashes.contains_key(&action_hash) {
        return Err(crate::error::GovernanceError::StaleProposal);
    }

    state.verify_action(msg, current_time_sec)
}
