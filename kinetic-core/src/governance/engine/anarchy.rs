//! Anarchy (development) protocol engine driver.
//!
//! Used for local testing and simulation where the network runs without any central
//! governance, timelocks, or update authorities. All privileged actions are universally rejected.

use crate::error::GovernanceError;
use crate::governance::types::{GovernanceEffect, GovernanceState, SignedGovernanceMessage};
use crate::traits::GovernanceEngine;

/// Development-only engine driver where all governance modifications are rejected.
///
/// Represents a pure decentralized state with no Root or Council keys.
pub struct AnarchyEngine;

impl GovernanceEngine for AnarchyEngine {
    /// Universally rejects all governance actions.
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
