//! Permissionless network action engine driver.
//!
//! Used for local testing and simulation where the network runs without any central
//! authority. All privileged network actions are universally rejected.

use crate::error::ActionError;
use crate::traits::ActionEngine;
use crate::types::{ActionConfig, ActionEffect, ActionState, SignedActionMessage};

/// Development-only engine driver where all modifications are rejected.
///
/// Represents a pure decentralized state where the Sovereign key has no administrative authority.
pub struct PermissionlessEngine;

impl ActionEngine for PermissionlessEngine {
    /// Universally rejects all network actions.
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
        // No network actions (updates, name unmappings) are allowed.
        Err(ActionError::ActionDisabled)
    }

    fn execute_action(
        &self,
        _state: &mut ActionState,
        _msg: &SignedActionMessage,
        _current_kyn: kinetic_types::clock::Kyn,
        _config: &ActionConfig,
    ) -> Option<ActionEffect> {
        unreachable!("Network action execution is permanently disabled in Permissionless mode")
    }
}
