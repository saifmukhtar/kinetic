use crate::error::GovernanceError;
use crate::types::{GovernanceEffect, GovernanceState, SignedGovernanceMessage};

pub trait GovernanceEngine: Send + Sync {
    /// Verifies whether a signed governance message meets threshold and timelock requirements.
    ///
    /// Does **not** mutate `state` on its own — state changes only happen in
    /// [`execute_action`](Self::execute_action).
    ///
    /// # Returns
    ///
    /// - `Ok(Some(effect))` if the message is valid and immediately executable (no timelock).
    /// - `Ok(None)` if the message is valid but waiting in a timelock queue.
    ///
    /// # Errors
    ///
    /// - Returns [`GovernanceError::InvalidSignature`] (`KIN-ACN-007`) if required signatures or threshold are not met.
    /// - Returns [`GovernanceError::StaleProposal`] (`KIN-ACN-005`) if the proposal timestamp is outside the replay window.
    /// - Returns [`GovernanceError::GovernanceDisabled`] (`KIN-ACN-003`) if governance actions are disabled in this mode.
    /// - Returns [`GovernanceError::KeyLengthMismatch`] (`KIN-ACN-004`) if a key length is invalid.
    /// - Returns [`GovernanceError::MissingRootKey`] (`KIN-ACN-001`) if the root key is unconfigured.
    fn verify_action(
        &self,
        state: &mut GovernanceState,
        msg: &SignedGovernanceMessage,
        current_kyn: kinetic_types::clock::Kyn,
        config: &crate::types::GovernanceConfig,
    ) -> Result<Option<GovernanceEffect>, GovernanceError>;

    /// Executes a previously verified governance action, applying state changes.
    ///
    /// Must only be called after [`verify_action`](Self::verify_action) returns `Ok(_)`.
    /// The `wait_time` parameter is the remaining timelock seconds to apply for deferred effects.
    ///
    /// # Returns
    ///
    /// `Some(effect)` if a state-changing side effect was produced (e.g. key rotation,
    /// council change). `None` if the action was enqueued for a future timelock.
    fn execute_action(
        &self,
        state: &mut GovernanceState,
        msg: &SignedGovernanceMessage,
        current_kyn: kinetic_types::clock::Kyn,
        config: &crate::types::GovernanceConfig,
    ) -> Option<GovernanceEffect>;
}
