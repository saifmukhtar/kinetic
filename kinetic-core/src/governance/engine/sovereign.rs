//! Sovereign (root-only) protocol engine driver.
//!
//! In Sovereign mode, the network relies entirely on the offline Root key for all decisions.
//! Council member signatures are ignored, and threshold logic is bypassed. Used primarily
//! for private deployments or the earliest stages of bootstrap.

use crate::error::GovernanceError;
use crate::governance::types::{
    GovernanceAction, GovernanceEffect, GovernanceState, SignedGovernanceMessage, verify_signature,
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
    /// - Returns [`GovernanceError::StaleProposal`] if the proposal timestamp exceeds [`crate::constants::MAX_AGE_KYNS`].
    /// - Returns [`GovernanceError::InvalidPremiumNameLength`] if a premium name is not 1 character.
    /// - Returns [`GovernanceError::InsufficientSignatures`] if the Root key signature is missing or invalid.
    fn verify_action(
        &self,
        state: &mut GovernanceState,
        msg: &SignedGovernanceMessage,
        current_kyn: u64,
    ) -> Result<Option<GovernanceEffect>, GovernanceError> {
        let max_age_kyns = crate::constants::MAX_AGE_KYNS;
        if current_kyn.abs_diff(msg.timestamp_kyn) > max_age_kyns {
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
                GovernanceAction::MapPrime { name, .. } => {
                    if name.len() != 1
                        || !name
                            .chars()
                            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
                    {
                        return Err(GovernanceError::UnnormalizedName);
                    }
                    if state.mapped_prime_names.contains_key(name) {
                        return Err(GovernanceError::AlreadyMapped);
                    }
                }
                GovernanceAction::UnmapPrime { name } => {
                    if name.len() != 1
                        || !name
                            .chars()
                            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
                    {
                        return Err(GovernanceError::UnnormalizedName);
                    }
                    if !state.mapped_prime_names.contains_key(name) {
                        return Err(GovernanceError::NotMapped);
                    }
                }
                GovernanceAction::MapInfra { name, .. } => {
                    if !crate::types::protocol::PROTOCOL_NAMES.contains(&name.as_str()) {
                        return Err(GovernanceError::InvalidProtocolName);
                    }
                    if state.mapped_infra_names.contains_key(name) {
                        return Err(GovernanceError::AlreadyMapped);
                    }
                }
                GovernanceAction::UnmapInfra { name } => {
                    if !crate::types::protocol::PROTOCOL_NAMES.contains(&name.as_str()) {
                        return Err(GovernanceError::InvalidProtocolName);
                    }
                    if !state.mapped_infra_names.contains_key(name) {
                        return Err(GovernanceError::NotMapped);
                    }
                }
                GovernanceAction::RotateRootKey { new_key } => {
                    if new_key.len() != 1952 {
                        return Err(GovernanceError::KeyLengthMismatch);
                    }
                }
                GovernanceAction::EmergencyHalt | GovernanceAction::EmergencyResume => {
                    // No additional verification needed for halt/resume,
                    // root key signature is sufficient authorization.
                }
            }

            let effect = self.execute_action(state, msg, current_kyn);
            return Ok(effect);
        }

        Err(GovernanceError::InsufficientSignatures)
    }

    fn execute_action(
        &self,
        state: &mut GovernanceState,
        msg: &SignedGovernanceMessage,
        current_kyn: u64,
    ) -> Option<GovernanceEffect> {
        let action_hash = GovernanceState::hash_action(msg);
        state.executed_hashes.insert(action_hash, msg.timestamp_kyn);

        match &msg.action {
            GovernanceAction::MapPrime {
                name,
                target_pubkey,
            } => {
                state
                    .mapped_prime_names
                    .insert(name.clone(), target_pubkey.clone());
                Some(GovernanceEffect::PrimeMapped {
                    name: name.clone(),
                    target_pubkey: target_pubkey.clone(),
                })
            }
            GovernanceAction::UnmapPrime { name } => {
                state.mapped_prime_names.remove(name);
                Some(GovernanceEffect::PrimeUnmapped { name: name.clone() })
            }
            GovernanceAction::MapInfra {
                name,
                target_pubkey,
            } => {
                state
                    .mapped_infra_names
                    .insert(name.clone(), target_pubkey.clone());
                Some(GovernanceEffect::InfraMapped {
                    name: name.clone(),
                    target_pubkey: target_pubkey.clone(),
                })
            }
            GovernanceAction::UnmapInfra { name } => {
                state.mapped_infra_names.remove(name);
                Some(GovernanceEffect::InfraUnmapped { name: name.clone() })
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
                    if state.halt_start_kyn.is_none() {
                        state.halt_start_kyn = Some(current_kyn);
                    }
                }
                Some(GovernanceEffect::NetworkHalted)
            }
            GovernanceAction::EmergencyResume => {
                if state.is_halted {
                    state.is_halted = false;
                    let start_kyn = state.halt_start_kyn.take().unwrap_or(current_kyn);
                    let paused_kyns = current_kyn.saturating_sub(start_kyn);
                    state.total_paused_kyns = state.total_paused_kyns.saturating_add(paused_kyns);
                    state.pause_history.push((start_kyn, current_kyn));
                }
                Some(GovernanceEffect::NetworkResumed)
            }
        }
    }
}
