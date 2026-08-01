//! Sovereign (root-only) protocol engine driver.
//!
//! In Sovereign mode, the network relies entirely on the offline Root key for all decisions.
//! Council member signatures are ignored, and threshold logic is bypassed. Used primarily
//! for private deployments or the earliest stages of bootstrap.

use crate::error::GovernanceError;
use crate::governance::types::{
    verify_signature, GovernanceAction, GovernanceEffect, GovernanceState, SignedGovernanceMessage,
};
use crate::traits::GovernanceEngine;

/// Single-signer governance engine driver controlled exclusively by the Founder Root key.
pub struct SovereignEngine;

impl GovernanceEngine for SovereignEngine {
    /// Verifies that the proposal is signed by the Founder Root key.
    ///
    ///
    /// # Errors
    ///
    /// - Returns [`GovernanceError::StaleProposal`] if the proposal timestamp exceeds [`crate::constants::MAX_AGE_SECONDS`].
    /// - Returns [`GovernanceError::InvalidPremiumNameLength`] if a premium name is not 1 character.
    /// - Returns [`GovernanceError::InsufficientSignatures`] if the Root key signature is missing or invalid.
    fn verify_action(
        &self,
        state: &mut GovernanceState,
        msg: &SignedGovernanceMessage,
        current_time_sec: u64,
    ) -> Result<Option<GovernanceEffect>, GovernanceError> {
        if current_time_sec.abs_diff(msg.timestamp_sec) > crate::constants::MAX_AGE_SECONDS {
            return Err(GovernanceError::StaleProposal);
        }

        let root_key = state.get_root_key()?;
        let action_bytes = msg.to_canonical_bytes();

        let root_signed = msg
            .signatures
            .iter()
            .any(|sig| verify_signature(&root_key, &action_bytes, sig));

        if root_signed {
            match &msg.action {
                GovernanceAction::GrantPremiumName { name, .. } => {
                    let label = name
                        .strip_suffix(crate::constants::TLD_SUFFIX)
                        .unwrap_or(name);
                    if label.len() != 1 {
                        return Err(GovernanceError::InvalidPremiumNameLength);
                    }
                }
                GovernanceAction::RevokePremiumName { name } => {
                    let label = name
                        .strip_suffix(crate::constants::TLD_SUFFIX)
                        .unwrap_or(name);
                    if label.len() != 1 {
                        return Err(GovernanceError::InvalidPremiumNameLength);
                    }
                }
                GovernanceAction::RotateRootKey { new_key } => {
                    if new_key.len() != 1952 {
                        return Err(GovernanceError::KeyLengthMismatch);
                    }
                }
                GovernanceAction::EmergencyHalt | GovernanceAction::EmergencyResume { .. } => {
                    // No additional verification needed for halt/resume,
                    // root key signature is sufficient authorization.
                }
            }

            let effect = self.execute_action(state, msg, current_time_sec);
            return Ok(effect);
        }

        Err(GovernanceError::InsufficientSignatures)
    }

    fn execute_action(
        &self,
        state: &mut GovernanceState,
        msg: &SignedGovernanceMessage,
        current_time_sec: u64,
    ) -> Option<GovernanceEffect> {
        let action_hash = GovernanceState::hash_action(msg);
        state.executed_hashes.insert(action_hash, current_time_sec);

        match &msg.action {
            GovernanceAction::GrantPremiumName {
                name,
                target_pubkey,
            } => Some(GovernanceEffect::PremiumNameGranted {
                name: name.clone(),
                target_pubkey: target_pubkey.clone(),
            }),
            GovernanceAction::RevokePremiumName { name } => {
                Some(GovernanceEffect::PremiumNameRevoked { name: name.clone() })
            }
            GovernanceAction::RotateRootKey { new_key } => {
                state.active_root_key = Some(new_key.clone());
                Some(GovernanceEffect::RootKeyRotated {
                    new_key: new_key.clone(),
                })
            }
            GovernanceAction::EmergencyHalt => {
                if !state.is_halted {
                    state.is_halted = true;
                }
                Some(GovernanceEffect::NetworkHalted)
            }
            GovernanceAction::EmergencyResume { paused_rounds } => {
                if state.is_halted {
                    state.is_halted = false;
                    state.total_paused_rounds =
                        state.total_paused_rounds.saturating_add(*paused_rounds);
                }
                Some(GovernanceEffect::NetworkResumed)
            }
        }
    }
}
