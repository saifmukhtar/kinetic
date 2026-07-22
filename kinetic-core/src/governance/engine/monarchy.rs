//! Single-key Founder governance engine driver.
//!
//! In Monarchy mode, the network relies entirely on the offline Root key for all decisions.
//! Council member signatures are ignored, and threshold logic is bypassed. Used primarily
//! for private deployments or the earliest stages of bootstrap.

use crate::error::GovernanceError;
use crate::governance::types::{
    verify_signature, GovernanceAction, GovernanceEffect, GovernanceState, SignedGovernanceMessage,
};
use crate::traits::GovernanceEngine;

/// Single-signer governance engine driver controlled exclusively by the Founder Root key.
pub struct MonarchyEngine;

impl GovernanceEngine for MonarchyEngine {
    /// Verifies that the proposal is signed by the Founder Root key.
    ///
    /// # Errors
    ///
    /// - Returns [`GovernanceError::StaleProposal`] if the proposal timestamp exceeds [`crate::constants::MAX_AGE_SECONDS`].
    /// - Returns [`GovernanceError::NotPendingOrVetoed`] if the target action hash is not pending in timelock queue.
    /// - Returns [`GovernanceError::TimelockNotExpired`] if mandatory timelocks have not elapsed.
    /// - Returns [`GovernanceError::InvalidPremiumNameLength`] if a premium name is not 1 character.
    /// - Returns [`GovernanceError::InsufficientSignatures`] if the Root key signature is missing.
    fn verify_action(
        &self,
        state: &mut GovernanceState,
        msg: &SignedGovernanceMessage,
        current_time_sec: u64,
    ) -> Result<Option<GovernanceEffect>, GovernanceError> {
        if current_time_sec.abs_diff(msg.timestamp_sec) > crate::constants::MAX_AGE_SECONDS {
            return Err(GovernanceError::StaleProposal);
        }

        if let GovernanceAction::ExecuteTimelock { target_hash } = &msg.action {
            let is_mature = if let Some((start, wait, _)) = state.pending_updates.get(target_hash) {
                current_time_sec >= start.saturating_add(*wait)
            } else {
                return Err(GovernanceError::NotPendingOrVetoed);
            };
            if !is_mature {
                return Err(GovernanceError::TimelockNotExpired);
            }
        }

        let root_key = state.get_root_key()?;
        let action_bytes = msg.to_canonical_bytes();

        let root_signed = msg
            .signatures
            .iter()
            .any(|sig| verify_signature(&root_key, &action_bytes, sig));

        if root_signed {
            if let GovernanceAction::GrantPremiumName { name, .. } = &msg.action {
                let label = name
                    .strip_suffix(crate::constants::TLD_SUFFIX)
                    .unwrap_or(name);
                if label.len() != 1 {
                    return Err(GovernanceError::InvalidPremiumNameLength);
                }
            }
            let wait_time = if let GovernanceAction::UpdateBinary { .. } = &msg.action {
                Some(24 * 60 * 60) // 1 day timelock for monarchy updates
            } else {
                None
            };
            return Ok(self.execute_action(state, msg, current_time_sec, wait_time));
        }

        Err(GovernanceError::InsufficientSignatures)
    }

    fn execute_action(
        &self,
        state: &mut GovernanceState,
        msg: &SignedGovernanceMessage,
        current_time_sec: u64,
        wait_time: Option<u64>,
    ) -> Option<GovernanceEffect> {
        let mut effect = None;
        match &msg.action {
            GovernanceAction::UpdateBinary {
                manifest_hash,
                mirrors,
                ..
            } => {
                if let Some(wait_sec) = wait_time {
                    let action_hash = GovernanceState::hash_action(msg);
                    state
                        .pending_updates
                        .insert(action_hash, (current_time_sec, wait_sec, mirrors.clone()));
                } else {
                    effect = Some(GovernanceEffect::TriggerOTA {
                        manifest_hash: *manifest_hash,
                        mirrors: mirrors.clone(),
                    });
                }
            }
            GovernanceAction::VetoUpdate { target_hash } => {
                state.pending_updates.remove(target_hash);
                state.vetoed_hashes.insert(*target_hash);
            }
            GovernanceAction::ExecuteTimelock { target_hash } => {
                if let Some((_, _, mirrors)) = state.pending_updates.remove(target_hash) {
                    effect = Some(GovernanceEffect::TriggerOTA {
                        manifest_hash: *target_hash,
                        mirrors,
                    });
                }
            }
            GovernanceAction::GrantPremiumName {
                name,
                target_pubkey,
            } => {
                effect = Some(GovernanceEffect::PremiumNameGranted {
                    name: name.clone(),
                    target_pubkey: target_pubkey.clone(),
                });
            }
            GovernanceAction::RevokePremiumName { name } => {
                effect = Some(GovernanceEffect::PremiumNameRevoked { name: name.clone() });
            }
            // Irrelevant in monarchy
            GovernanceAction::AppointMember { .. }
            | GovernanceAction::SelfAppointCouncilMember { .. }
            | GovernanceAction::RemoveCouncilMember { .. }
            | GovernanceAction::LockCouncil => {}

            GovernanceAction::RotateRootKey { new_key } => {
                state.dynamic_root_key = Some(new_key.clone());
            }
            GovernanceAction::RotateGuardKey { new_key } => {
                state.dynamic_guard_key = Some(new_key.clone());
            }
        }
        effect
    }
}
