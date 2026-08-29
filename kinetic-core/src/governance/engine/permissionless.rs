//! Permissionless (development) protocol engine driver.
//!
//! Used for local testing and simulation where the network runs without any central
//! governance or update authorities. All privileged actions are universally rejected.

use crate::error::GovernanceError;
use crate::governance::types::{GovernanceEffect, GovernanceState, SignedGovernanceMessage};
use crate::traits::GovernanceEngine;

/// Development-only engine driver where all governance modifications are rejected.
///
/// Represents a pure decentralized state with no Root or Council keys.
pub struct PermissionlessEngine;

impl GovernanceEngine for PermissionlessEngine {
    /// Universally rejects all governance actions.
    ///
    /// # Errors
    ///
    /// - Always returns [`GovernanceError::GovernanceDisabled`].
    fn verify_action(
        &self,
        _state: &mut GovernanceState,
        _msg: &SignedGovernanceMessage,
        _current_kyn: u64,
    ) -> Result<Option<GovernanceEffect>, GovernanceError> {
        // In Permissionless mode, the network is perfectly immutable.
        // No governance actions (updates, name revocations) are allowed.
        Err(GovernanceError::GovernanceDisabled)
    }

    fn execute_action(
        &self,
        _state: &mut GovernanceState,
        _msg: &SignedGovernanceMessage,
        _current_kyn: u64,
    ) -> Option<GovernanceEffect> {
        unreachable!("Governance execution is permanently disabled in Permissionless mode")
    }
}
