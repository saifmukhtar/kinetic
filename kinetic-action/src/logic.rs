//! Core action state transitions and message signature aggregation.
//!
//! Implements the `ActionState` mutating operations that are called by the
//! engine (Sovereign or Permissionless) during execution.
//!
//! - [`ActionState::new`] — genesis state initialization
//! - [`ActionState::hash_action`] — deterministic SHA-256 action hash derivation
//! - [`ActionState::prune`] — stale proposal garbage collection
//! - [`ActionState::get_sovereign_key`] — root verification key retrieval
//! - [`ActionState::verify_action`] — engine action verification
//! - [`ActionState::execute_action`] — engine action execution

use std::collections::HashMap;

use crate::error::ActionError;
use crate::types::{
    ActionConfig, ActionEffect, ActionState, Hash256, PublicKeyBytes,
    SignedActionMessage,
};

/// Validates that the static cryptographic keys required for action have been correctly initialized.
///
/// # Errors
///
/// - Returns [`ActionError::MissingSovereignKey`] if the root key hex string is unconfigured or invalid.
/// - Returns [`ActionError::KeyLengthMismatch`] if a public key is not exactly 1,952 bytes.
pub fn validate_keys_initialized(
    sovereign_key_hex: &str,
    is_dev_mode: bool,
) -> Result<(), ActionError> {
    if is_dev_mode {
        return Ok(());
    }
    if sovereign_key_hex.contains("REPLACE_ME") {
        return Err(ActionError::MissingSovereignKey);
    }

    // Attempt to decode the hex just to validate its format.
    let bytes =
        hex::decode(sovereign_key_hex).map_err(|_| ActionError::MalformedSovereignKey)?;

    if bytes.len() != 1952 {
        return Err(ActionError::KeyLengthMismatch);
    }

    Ok(())
}

impl ActionState {
    /// Initializes a new [`ActionState`] at network genesis.
    ///
    /// The state starts in `ActionMode::Founder` with an empty council,
    /// no pending updates, and no prime mappings.
    ///
    /// # Returns
    ///
    /// A new `ActionState` ready for genesis block processing.
    pub fn new(genesis_kyn: kinetic_types::clock::Kyn) -> Self {
        Self {
            genesis_kyn,
            active_sovereign_key: None,
            is_halted: false,
            halt_start_kyn: None,
            total_paused_kyns: 0,
            pause_history: Vec::new(),
            executed_hashes: HashMap::new(),
            action_log: Vec::new(),
            mapped_prime_names: HashMap::new(),
            mapped_infra_names: HashMap::new(),
        }
    }

    /// Computes the SHA-256 action hash for a signed action message.
    ///
    /// The hash is derived from `SHA-256(msg.to_bytes())` and is used as the
    /// stable key for all subsequent state operations (timelock map, partial proposal map).
    ///
    /// # Returns
    ///
    /// A deterministic 32-byte `[u8; 32]` SHA-256 hash of the canonical message bytes.
    pub fn hash_action(msg: &SignedActionMessage) -> Hash256 {
        kinetic_primitives::sha256_hash(&msg.to_bytes())
    }

    /// Garbage collects the `executed_hashes` set.
    ///
    /// Items are pruned if they have been executed for more than the network's `MAX_AGE_KYNS`.
    /// This keeps the state file bounded.
    pub fn prune(&mut self, current_kyn: kinetic_types::clock::Kyn, config: &ActionConfig) {
        // Remove executed hashes older than the max age
        let max_age_kyns = config.max_age_kyns;
        self.executed_hashes
            .retain(|_, exec_kyn| current_kyn.0 <= exec_kyn.0 + max_age_kyns);
    }

    /// Retrieves the static root verifying key.
    ///
    /// # Errors
    ///
    /// Returns a `ActionError` if the key is missing, invalid, or has the wrong length.
    pub fn get_sovereign_key(
        &self,
        config: &ActionConfig,
    ) -> Result<PublicKeyBytes, ActionError> {
        if let Some(key) = &self.active_sovereign_key {
            return Ok(key.clone());
        }

        let bytes = hex::decode(&config.sovereign_key_hex)
            .map_err(|_| ActionError::MalformedSovereignKey)?;
        if bytes.len() != 1952 {
            return Err(ActionError::KeyLengthMismatch);
        }
        Ok(bytes)
    }

    /// Verifies whether a signed action message meets the quorum and validity rules to be executed.
    ///
    /// # Errors
    ///
    /// Returns a `ActionError` if the message is stale, signatures are insufficient, timelocks are not met, or other invariants are violated.
    pub fn verify_action(
        &mut self,
        msg: &SignedActionMessage,
        current_kyn: kinetic_types::clock::Kyn,
        config: &ActionConfig,
    ) -> Result<Option<ActionEffect>, ActionError> {
        crate::engine::get_active_engine(&config.action_model).verify_action(
            self,
            msg,
            current_kyn,
            config,
        )
    }

    /// Executes a verified action action, applying its state changes and returning any resulting effects.
    pub fn execute_action(
        &mut self,
        msg: &SignedActionMessage,
        current_kyn: kinetic_types::clock::Kyn,
        config: &ActionConfig,
    ) -> Option<ActionEffect> {
        crate::engine::get_active_engine(&config.action_model).execute_action(
            self,
            msg,
            current_kyn,
            config,
        )
    }
}

/// Processes an incoming action message, merging its signatures and executing the action if quorum is met.
///
/// # Errors
///
/// Returns a `ActionError` if the action fails verification or execution rules.
pub fn process_action_message(
    state: &mut ActionState,
    msg: &SignedActionMessage,
    current_kyn: kinetic_types::clock::Kyn,
    config: &ActionConfig,
) -> Result<Option<ActionEffect>, ActionError> {
    let effect = state.verify_action(msg, current_kyn, config)?;

    state.prune(current_kyn, config);

    let action_hash = ActionState::hash_action(msg);
    if state.executed_hashes.contains_key(&action_hash) {
        return Err(ActionError::AlreadyExecuted);
    }

    state.execute_action(msg, current_kyn, config);
    state.action_log.push(msg.clone());
    Ok(effect)
}
