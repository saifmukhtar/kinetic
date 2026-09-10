//! Sovereign (root-only) protocol engine driver.
//!
//! In Sovereign mode, the network relies entirely on the offline Root key for all decisions.
//! Council member signatures are ignored, and threshold logic is bypassed. Used primarily
//! for private deployments or the earliest stages of bootstrap.

use crate::error::ActionError;
use crate::traits::ActionEngine;
use crate::types::{
    NetworkAction, ActionConfig, ActionEffect, ActionState, SignedActionMessage,
    verify_signature,
};

/// Single-signer governance engine driver controlled exclusively by the Founder Root key.
pub struct SovereignEngine;

impl ActionEngine for SovereignEngine {
    /// Verifies that the proposal is signed by the Founder Root key.
    ///
    ///
    /// # Errors
    ///
    /// - Returns [`ActionError::StaleProposal`] if the proposal timestamp exceeds `config.max_age_kyns`.
    /// - Returns [`ActionError::InvalidPrimeLength`] if a prime name is not 1 character.
    /// - Returns [`ActionError::InvalidSignature`] if the Root key signature is missing or invalid.
    fn verify_action(
        &self,
        state: &mut ActionState,
        msg: &SignedActionMessage,
        current_kyn: kinetic_types::clock::Kyn,
        config: &ActionConfig,
    ) -> Result<Option<ActionEffect>, ActionError> {
        if current_kyn.0.abs_diff(msg.timestamp_kyn) > config.max_age_kyns {
            return Err(ActionError::StaleProposal);
        }

        let root_key = state.get_sovereign_key(config)?;
        let action_bytes = msg.to_bytes();

        let root_signed = msg
            .signatures
            .iter()
            .any(|sig| verify_signature(&root_key, &action_bytes, sig));

        if root_signed {
            let effect = match &msg.action {
                NetworkAction::MapPrime {
                    name,
                    target_pubkey,
                } => {
                    if name.len() != 1 {
                        return Err(ActionError::InvalidPrimeLength);
                    }
                    if !name
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
                    {
                        return Err(ActionError::UnnormalizedName);
                    }
                    if target_pubkey.len() != 1952 {
                        return Err(ActionError::KeyLengthMismatch);
                    }
                    if state.mapped_prime_names.contains_key(name) {
                        return Err(ActionError::AlreadyMapped);
                    }
                    ActionEffect::PrimeMapped {
                        name: name.clone(),
                        target_pubkey: target_pubkey.clone(),
                    }
                }
                NetworkAction::UnmapPrime { name } => {
                    if name.len() != 1 {
                        return Err(ActionError::InvalidPrimeLength);
                    }
                    if !name
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
                    {
                        return Err(ActionError::UnnormalizedName);
                    }
                    if !state.mapped_prime_names.contains_key(name) {
                        return Err(ActionError::NotMapped);
                    }
                    ActionEffect::PrimeUnmapped { name: name.clone() }
                }
                NetworkAction::MapInfra {
                    name,
                    target_pubkey,
                } => {
                    if !kinetic_types::protocol::PROTOCOL_NAMES.contains(&name.as_str()) {
                        return Err(ActionError::InvalidProtocolName);
                    }
                    if target_pubkey.len() != 1952 {
                        return Err(ActionError::KeyLengthMismatch);
                    }
                    if state.mapped_infra_names.contains_key(name) {
                        return Err(ActionError::AlreadyMapped);
                    }
                    ActionEffect::InfraMapped {
                        name: name.clone(),
                        target_pubkey: target_pubkey.clone(),
                    }
                }
                NetworkAction::UnmapInfra { name } => {
                    if !kinetic_types::protocol::PROTOCOL_NAMES.contains(&name.as_str()) {
                        return Err(ActionError::InvalidProtocolName);
                    }
                    if !state.mapped_infra_names.contains_key(name) {
                        return Err(ActionError::NotMapped);
                    }
                    ActionEffect::InfraUnmapped { name: name.clone() }
                }
                NetworkAction::RotateRootKey { new_key } => {
                    if new_key.len() != 1952 {
                        return Err(ActionError::KeyLengthMismatch);
                    }
                    ActionEffect::RootKeyRotated {
                        new_key: new_key.clone(),
                    }
                }
                NetworkAction::EmergencyHalt => ActionEffect::NetworkHalted,
                NetworkAction::EmergencyResume => ActionEffect::NetworkResumed,
            };

            return Ok(Some(effect));
        }

        Err(ActionError::InvalidSignature)
    }

    fn execute_action(
        &self,
        state: &mut ActionState,
        msg: &SignedActionMessage,
        current_kyn: kinetic_types::clock::Kyn,
        _config: &ActionConfig,
    ) -> Option<ActionEffect> {
        let action_hash = ActionState::hash_action(msg);
        state
            .executed_hashes
            .insert(action_hash, kinetic_types::clock::Kyn(msg.timestamp_kyn));

        match &msg.action {
            NetworkAction::MapPrime {
                name,
                target_pubkey,
            } => {
                state
                    .mapped_prime_names
                    .insert(name.clone(), target_pubkey.clone());
                Some(ActionEffect::PrimeMapped {
                    name: name.clone(),
                    target_pubkey: target_pubkey.clone(),
                })
            }
            NetworkAction::UnmapPrime { name } => {
                state.mapped_prime_names.remove(name);
                Some(ActionEffect::PrimeUnmapped { name: name.clone() })
            }
            NetworkAction::MapInfra {
                name,
                target_pubkey,
            } => {
                state
                    .mapped_infra_names
                    .insert(name.clone(), target_pubkey.clone());
                Some(ActionEffect::InfraMapped {
                    name: name.clone(),
                    target_pubkey: target_pubkey.clone(),
                })
            }
            NetworkAction::UnmapInfra { name } => {
                state.mapped_infra_names.remove(name);
                Some(ActionEffect::InfraUnmapped { name: name.clone() })
            }
            NetworkAction::RotateRootKey { new_key } => {
                state.active_sovereign_key = Some(new_key.clone());
                Some(ActionEffect::RootKeyRotated {
                    new_key: new_key.clone(),
                })
            }
            NetworkAction::EmergencyHalt => {
                if !state.is_halted {
                    state.is_halted = true;
                    if state.halt_start_kyn.is_none() {
                        state.halt_start_kyn = Some(current_kyn);
                    }
                }
                Some(ActionEffect::NetworkHalted)
            }
            NetworkAction::EmergencyResume => {
                if state.is_halted {
                    state.is_halted = false;
                    let start_kyn = state.halt_start_kyn.take().unwrap_or(current_kyn);
                    let paused_kyns = current_kyn.0.saturating_sub(start_kyn.0);
                    state.total_paused_kyns = state.total_paused_kyns.saturating_add(paused_kyns);
                    state.pause_history.push((start_kyn, current_kyn));
                }
                Some(ActionEffect::NetworkResumed)
            }
        }
    }
}
