//! Interface definitions for action evaluation engines.
//!
//! Provides the core [`ActionEngine`] trait that all specific consensus modules
//! (e.g., Sovereign or Permissionless) must implement to validate and execute
//! incoming network actions.

use crate::error::ActionError;
use crate::types::{ActionEffect, ActionState, SignedNetworkAction};

/// Pluggable evaluator for signed network actions.
pub trait ActionEngine: Send + Sync {
    /// Verifies whether a signed network action meets all validity rules.
    ///
    /// Does **not** mutate `state` on its own — state changes only happen in
    /// [`execute_action`](Self::execute_action).
    ///
    /// # Returns
    ///
    /// - `Ok(Some(effect))` if the message is valid and executable.
    ///
    /// # Errors
    ///
    /// - Returns [`ActionError::InvalidSignature`] (`KIN-ACN-007`) if the required Sovereign signature is not met.
    /// - Returns [`ActionError::StaleProposal`] (`KIN-ACN-005`) if the proposal timestamp is outside the replay window.
    /// - Returns [`ActionError::ActionDisabled`] (`KIN-ACN-003`) if network actions are disabled in this mode.
    /// - Returns [`ActionError::KeyLengthMismatch`] (`KIN-ACN-004`) if a key length is invalid.
    /// - Returns [`ActionError::MissingSovereignKey`] (`KIN-ACN-001`) if the Sovereign key is unconfigured.
    fn verify_action(
        &self,
        state: &mut ActionState,
        msg: &SignedNetworkAction,
        current_kyn: kinetic_kyn::types::CurrentKyn,
        config: &crate::types::ActionConfig,
    ) -> Result<Option<ActionEffect>, ActionError>;

    /// Executes a previously verified network action, applying state changes.
    ///
    /// Must only be called after [`verify_action`](Self::verify_action) returns `Ok(_)`.
    ///
    /// # Returns
    ///
    /// `Some(effect)` if a state-changing side effect was produced (e.g. key rotation).
    fn execute_action(
        &self,
        state: &mut ActionState,
        msg: &SignedNetworkAction,
        current_kyn: kinetic_kyn::types::CurrentKyn,
        config: &crate::types::ActionConfig,
    ) -> Option<ActionEffect>;
}
