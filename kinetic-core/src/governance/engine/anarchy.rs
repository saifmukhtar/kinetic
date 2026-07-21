//! Immutable protocol engine driver.

use crate::error::GovernanceError;
use crate::governance::types::{GovernanceEffect, GovernanceState, SignedGovernanceMessage};
use crate::traits::GovernanceEngine;

/// Immutable protocol engine driver where all governance modifications are rejected.
pub struct AnarchyEngine;

impl GovernanceEngine for AnarchyEngine {
    /// Rejects all governance actions, preserving absolute protocol immutability.
    ///
    /// # Errors
    ///
    /// - Always returns [`GovernanceError::InsufficientSignatures`].
    fn verify_action(
        &self,
        _state: &mut GovernanceState,
        _msg: &SignedGovernanceMessage,
        _current_time_sec: u64,
    ) -> Result<Option<GovernanceEffect>, GovernanceError> {
        // In Anarchy mode, the network is perfectly immutable.
        // No governance actions (updates, name revocations) are allowed.
        Err(GovernanceError::InsufficientSignatures)
    }

    fn execute_action(
        &self,
        _state: &mut GovernanceState,
        _msg: &SignedGovernanceMessage,
        _current_time_sec: u64,
        _wait_time: Option<u64>,
    ) -> Option<GovernanceEffect> {
        None
    }
}
