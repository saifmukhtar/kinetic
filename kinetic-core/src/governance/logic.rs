//! Core governance state transitions and message signature aggregation.
//!
//! Implements the `GovernanceState` mutating operations that are called by the
//! active [`GovernanceEngine`](crate::traits::GovernanceEngine) after signature verification:
//! - [`GovernanceState::new`] — genesis state initialization
//! - [`GovernanceState::hash_action`] — deterministic SHA-256 action hash derivation
//! - [`GovernanceState::prune`] — stale proposal garbage collection
//! - [`GovernanceState::get_root_key`] — root verification key retrieval
//! - [`GovernanceState::verify_action`] — engine action verification
//! - [`GovernanceState::execute_action`] — engine action execution

use std::collections::HashMap;

use crate::constants::ROOT_PUBLIC_KEY_HEX;
use crate::error::GovernanceError;
use crate::governance::types::{
    GovernanceEffect, GovernanceState, Hash256, PublicKeyBytes, SignedGovernanceMessage,
};

/// Validates that the static cryptographic keys required for governance have been correctly initialized.
///
/// # Errors
///
/// - Returns [`GovernanceError::MissingRootKey`] if the root key hex string is unconfigured or invalid.
/// - Returns [`GovernanceError::KeyLengthMismatch`] if a public key is not exactly 1,952 bytes.
pub fn validate_keys_initialized() -> Result<(), GovernanceError> {
    if crate::config::is_dev_mode() {
        return Ok(());
    }
    if ROOT_PUBLIC_KEY_HEX.contains("REPLACE_ME") {
        return Err(GovernanceError::MissingRootKey);
    }

    let dummy_state = GovernanceState::new(kinetic_types::clock::Kyn(0));
    let _ = dummy_state.get_root_key()?;

    Ok(())
}

impl GovernanceState {
    /// Initializes a new [`GovernanceState`] at network genesis.
    ///
    /// The state starts in `GovernanceMode::Founder` with an empty council,
    /// no pending updates, and no prime mappings.
    ///
    /// # Returns
    ///
    /// A new `GovernanceState` ready for genesis block processing.
    pub fn new(genesis_kyn: kinetic_types::clock::Kyn) -> Self {
        Self {
            genesis_kyn,
            active_root_key: None,
            is_halted: false,
            halt_start_kyn: None,
            total_paused_kyns: 0,
            pause_history: Vec::new(),
            executed_hashes: HashMap::new(),
            mapped_prime_names: HashMap::new(),
            mapped_infra_names: HashMap::new(),
        }
    }

    /// Computes the SHA-256 action hash for a signed governance message.
    ///
    /// The hash is derived from `SHA-256(msg.to_bytes())` and is used as the
    /// stable key for all subsequent state operations (timelock map, partial proposal map).
    ///
    /// # Returns
    ///
    /// A deterministic 32-byte `[u8; 32]` SHA-256 hash of the canonical message bytes.
    pub fn hash_action(msg: &SignedGovernanceMessage) -> Hash256 {
        kinetic_primitives::sha256_hash(&msg.to_bytes())
    }

    /// Garbage collects the `executed_hashes` set.
    ///
    /// Items are pruned if they have been executed for more than the network's `MAX_AGE_KYNS`.
    /// This keeps the state file bounded.
    pub fn prune(&mut self, current_kyn: kinetic_types::clock::Kyn) {
        // Remove executed hashes older than the max age
        let max_age_kyns = crate::constants::MAX_AGE_KYNS;
        self.executed_hashes
            .retain(|_, exec_kyn| current_kyn.0 <= exec_kyn.0 + max_age_kyns);
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
            hex::decode(ROOT_PUBLIC_KEY_HEX).map_err(|_| GovernanceError::MalformedRootKey)?;
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
        current_kyn: kinetic_types::clock::Kyn,
    ) -> Result<Option<GovernanceEffect>, GovernanceError> {
        crate::governance::engine::get_active_engine().verify_action(self, msg, current_kyn)
    }

    /// Executes a verified governance action, applying its state changes and returning any resulting effects.
    pub fn execute_action(
        &mut self,
        msg: &SignedGovernanceMessage,
        current_kyn: kinetic_types::clock::Kyn,
    ) -> Option<GovernanceEffect> {
        crate::governance::engine::get_active_engine().execute_action(self, msg, current_kyn)
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
    current_kyn: kinetic_types::clock::Kyn,
) -> Result<Option<GovernanceEffect>, GovernanceError> {
    let effect = state.verify_action(msg, current_kyn)?;

    state.prune(current_kyn);

    let action_hash = GovernanceState::hash_action(msg);
    if state.executed_hashes.contains_key(&action_hash) {
        return Err(GovernanceError::AlreadyExecuted);
    }

    state.execute_action(msg, current_kyn);
    Ok(effect)
}
