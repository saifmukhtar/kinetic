//! Permissionless (development) protocol engine driver.
//!
//! Used for local testing and simulation where the network runs without any central
//! governance or update authorities. All privileged actions are universally rejected.

use crate::error::ActionError;
use crate::traits::ActionEngine;
use crate::types::{ActionConfig, ActionEffect, ActionState, SignedActionMessage};

/// Development-only engine driver where all governance modifications are rejected.
///
/// Represents a pure decentralized state with no Root or Council keys.
pub struct PermissionlessEngine;

impl ActionEngine for PermissionlessEngine {
    /// Universally rejects all governance actions.
    ///
    /// # Errors
    ///
    /// - Always returns [`ActionError::ActionDisabled`].
    fn verify_action(
        &self,
        _state: &mut ActionState,
        _msg: &SignedActionMessage,
        _current_kyn: kinetic_types::clock::Kyn,
        _config: &ActionConfig,
    ) -> Result<Option<ActionEffect>, ActionError> {
        // In Permissionless mode, the network is perfectly immutable.
        // No governance actions (updates, name revocations) are allowed.
        Err(ActionError::ActionDisabled)
    }

    fn execute_action(
        &self,
        _state: &mut ActionState,
        _msg: &SignedActionMessage,
        _current_kyn: kinetic_types::clock::Kyn,
        _config: &ActionConfig,
    ) -> Option<ActionEffect> {
        unreachable!("Governance execution is permanently disabled in Permissionless mode")
    }
}
