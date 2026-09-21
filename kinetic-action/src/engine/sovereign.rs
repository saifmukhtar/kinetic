//! Sovereign network action engine driver.
//!
//! In Sovereign mode, the network relies entirely on the offline Sovereign key for all decisions.
//! Used primarily for private deployments or the earliest stages of bootstrap.

use crate::error::ActionError;
use crate::traits::ActionEngine;
use crate::types::{
    ActionConfig, ActionEffect, ActionState, NetworkAction, SignedActionMessage, verify_sovereign_signature,
};

/// Single-signer network action engine driver controlled exclusively by the Sovereign key.
pub struct SovereignEngine;

impl ActionEngine for SovereignEngine {
    /// Verifies that the proposal is signed by the Sovereign key.
    ///
    ///
    /// # Errors
    ///
    /// - Returns [`ActionError::StaleProposal`] if the proposal timestamp exceeds `config.max_age_kyns`.

    /// - Returns [`ActionError::InvalidSignature`] if the Sovereign signature is missing or invalid.
    fn verify_action(
        &self,
        state: &mut ActionState,
        msg: &SignedActionMessage,
        current_kyn: kinetic_kyn::types::Kyn,
        config: &ActionConfig,
    ) -> Result<Option<ActionEffect>, ActionError> {
        if current_kyn.0.abs_diff(msg.timestamp_kyn.0) > config.max_age_kyns {
            return Err(ActionError::StaleProposal);
        }

        let sovereign_key = state.get_sovereign_key(config)?;
        let action_bytes = msg.to_bytes();

        let is_sovereign_signed = msg
            .sovereign_signatures
            .iter()
            .any(|sig| verify_sovereign_signature(&sovereign_key, &action_bytes, sig));

        if is_sovereign_signed {
            let effect = match &msg.action {


                NetworkAction::RotateSovereignKey { new_key } => {
                    if new_key.len() != kinetic_primitives::KINETIC_PUBKEY_LENGTH {
                        return Err(ActionError::KeyLengthMismatch);
                    }
                    ActionEffect::SovereignKeyRotated {
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
        current_kyn: kinetic_kyn::types::Kyn,
        _config: &ActionConfig,
    ) -> Option<ActionEffect> {
        let action_hash = ActionState::hash_action(msg);
        state
            .executed_hashes
            .insert(action_hash, msg.timestamp_kyn);

        match &msg.action {


            NetworkAction::RotateSovereignKey { new_key } => {
                state.active_sovereign_key = Some(new_key.as_bytes().to_vec());
                Some(ActionEffect::SovereignKeyRotated {
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
