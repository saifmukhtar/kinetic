//! Core network action state transitions and signature aggregation.
//!
//! Implements the `ActionState` mutating operations that are called by the
//! engine (Sovereign or Permissionless) during execution.
//!
//! - [`ActionState::new`] — genesis state initialization
//! - [`ActionState::hash_action`] — deterministic SHA-256 action hash derivation
//! - [`ActionState::prune`] — stale proposal pruning
//! - [`ActionState::get_sovereign_key`] — Sovereign verification key retrieval
//! - [`ActionState::verify_action`] — engine action verification
//! - [`ActionState::execute_action`] — engine action execution

use std::collections::HashMap;

use crate::error::ActionError;
use crate::types::{
    ActionConfig, ActionEffect, ActionState, Hash256, SignedActionMessage,
};

/// Validates that the static cryptographic keys required for network actions have been correctly initialized.
///
/// # Errors
///
/// - Returns [`ActionError::MissingSovereignKey`] if the Sovereign key hex string is unconfigured or invalid.
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
    let bytes = hex::decode(sovereign_key_hex).map_err(|_| ActionError::MalformedSovereignKey)?;

    if bytes.len() != kinetic_primitives::KINETIC_PUBKEY_LENGTH {
        return Err(ActionError::KeyLengthMismatch);
    }

    Ok(())
}

impl ActionState {
    /// Initializes a new [`ActionState`] at network genesis.
    ///
    /// The state starts with no pending updates and no active mappings.
    ///
    /// # Returns
    ///
    /// A new `ActionState` ready for genesis block processing.
    pub fn new(genesis_kyn: kinetic_kyn::types::Kyn) -> Self {
        Self {
            genesis_kyn,
            active_sovereign_key: None,
            is_halted: false,
            halt_start_kyn: None,
            total_paused_kyns: 0,
            pause_history: Vec::new(),
            executed_hashes: HashMap::new(),
            action_log: Vec::new(),

        }
    }

    /// Computes the SHA-256 action hash for a signed action message.
    ///
    /// The hash is derived from `SHA-256(msg.to_bytes())` and is used as the
    /// stable key for all subsequent state operations (e.g. deduplicating executed actions).
    ///
    /// # Examples
    /// ```rust,ignore
    /// use kinetic_action::types::ActionState;
    /// // let hash = ActionState::hash_action(&signed_msg);
    /// ```
    ///
    /// # Returns
    ///
    /// A deterministic 32-byte `[u8; 32]` SHA-256 hash of the canonical message bytes.
    pub fn hash_action(msg: &SignedActionMessage) -> Hash256 {
        kinetic_primitives::sha256_hash(&msg.to_bytes())
    }

    /// Prunes the `executed_hashes` set.
    ///
    /// Items are pruned if they have been executed for more than the network's `MAX_AGE_KYNS`.
    /// This keeps the state file bounded.
    pub fn prune(&mut self, current_kyn: kinetic_kyn::types::Kyn, config: &ActionConfig) {
        // Remove executed hashes older than the max age
        let max_age_kyns = config.max_age_kyns;
        self.executed_hashes
            .retain(|_, exec_kyn| current_kyn.0 <= exec_kyn.0 + max_age_kyns);
    }

    /// Retrieves the static Sovereign verifying key.
    ///
    /// # Errors
    ///
    /// Returns an [`ActionError`] if the key is missing, invalid, or has the wrong length.
    pub fn get_sovereign_key(&self, config: &ActionConfig) -> Result<kinetic_primitives::kinetic_keypair::SovereignPubKey, ActionError> {
        if let Some(key) = &self.active_sovereign_key {
            return Ok(kinetic_primitives::kinetic_keypair::SovereignPubKey(key.clone()));
        }

        let bytes = hex::decode(&config.sovereign_key_hex)
            .map_err(|_| ActionError::MalformedSovereignKey)?;
        if bytes.len() != kinetic_primitives::KINETIC_PUBKEY_LENGTH {
            return Err(ActionError::KeyLengthMismatch);
        }
        Ok(kinetic_primitives::kinetic_keypair::SovereignPubKey(bytes))
    }

    /// Verifies whether a signed action message meets validity rules to be executed.
    ///
    /// # Errors
    ///
    /// Returns an [`ActionError`] if the message is stale, the signature is missing, or invariants are violated.
    pub fn verify_action(
        &mut self,
        msg: &SignedActionMessage,
        current_kyn: kinetic_kyn::types::Kyn,
        config: &ActionConfig,
    ) -> Result<Option<ActionEffect>, ActionError> {
        crate::engine::get_active_engine(&config.action_model).verify_action(
            self,
            msg,
            current_kyn,
            config,
        )
    }

    /// Executes a verified network action, applying its state changes and returning any resulting effects.
    pub fn execute_action(
        &mut self,
        msg: &SignedActionMessage,
        current_kyn: kinetic_kyn::types::Kyn,
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

/// Processes an incoming action message, executing the action if it is valid.
///
/// # Errors
///
/// Returns an [`ActionError`] if the action fails verification or execution rules.
pub fn process_action_message(
    state: &mut ActionState,
    msg: &SignedActionMessage,
    current_kyn: kinetic_kyn::types::Kyn,
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
