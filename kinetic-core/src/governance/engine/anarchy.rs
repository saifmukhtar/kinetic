use crate::error::GovernanceError;
use crate::governance::types::{GovernanceEffect, GovernanceState, SignedGovernanceMessage};
use crate::traits::GovernanceEngine;

pub struct AnarchyEngine;

impl GovernanceEngine for AnarchyEngine {
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
