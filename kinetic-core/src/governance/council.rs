use std::collections::HashSet;
use ed25519_dalek::Verifier;

use crate::error::GovernanceError;
use super::types::{GovernanceAction, GovernanceEffect, GovernanceState, SignedGovernanceMessage};

pub fn verify_action(
    state: &mut GovernanceState,
    msg: &SignedGovernanceMessage,
    current_time_sec: u64,
) -> Result<Option<GovernanceEffect>, GovernanceError> {
    let guard_key_opt = state.get_guard_key()?;
    let action_bytes = msg.to_canonical_bytes();

    if let GovernanceAction::VetoUpdate { .. } = &msg.action {
        if let Some(guard_key) = guard_key_opt {
            if msg.signatures.iter().any(|sig| guard_key.verify(&action_bytes, sig).is_ok()) {
                return Ok(state.execute_action(msg, current_time_sec, None));
            }
        }
        return Err(GovernanceError::InvalidGuardSignature);
    }

    if let GovernanceAction::EmergencyReset { override_mode, .. } = &msg.action {
        let action_hash = GovernanceState::hash_action(msg);
        if state.vetoed_hashes.contains(&action_hash) {
            return Err(GovernanceError::EmergencyResetVetoed);
        }
        
        let root_key = state.get_root_key()?;
        let root_signed = msg
            .signatures
            .iter()
            .any(|sig| root_key.verify(&action_bytes, sig).is_ok());
            
        let guard_signed = if let Some(guard_key) = guard_key_opt {
            msg.signatures.iter().any(|sig| guard_key.verify(&action_bytes, sig).is_ok())
        } else {
            false
        };

        if !root_signed {
            return Err(GovernanceError::EmergencyResetRequiresRoot);
        }
        if !*override_mode && !guard_signed {
            return Err(GovernanceError::EmergencyResetRequiresGuard);
        }

        return Ok(state.execute_action(msg, current_time_sec, None));
    }

    if let GovernanceAction::GrantPremiumName { name, .. } | GovernanceAction::RevokePremiumName { name } = &msg.action {
        let label = name.strip_suffix(".kin").unwrap_or(name);
        if label.len() != 1 {
            return Err(GovernanceError::InvalidPremiumNameLength);
        }
    }

    let mut counted_members = HashSet::new();
    let mut valid_signers = HashSet::new();
    for sig in &msg.signatures {
        for (idx, member) in state.active_council.iter().enumerate() {
            if !counted_members.contains(&idx) && member.verify(&action_bytes, sig).is_ok() {
                counted_members.insert(idx);
                valid_signers.insert(*member);
                break;
            }
        }
    }

    let valid_council_sigs = counted_members.len();

    let required_signatures = match &msg.action {
        GovernanceAction::AppointMember { .. } | GovernanceAction::UpdateBinary { .. } => {
            (msg.council_size_at_proposal as usize * 69) / 100 + 1
        }
        GovernanceAction::SelfAppointCouncilMember { .. }
        | GovernanceAction::GrantPremiumName { .. }
        | GovernanceAction::RevokePremiumName { .. } => {
            (msg.council_size_at_proposal as usize * 90) / 100 + 1
        }
        GovernanceAction::RemoveCouncilMember { .. } => {
            let target_active = msg.council_size_at_proposal.saturating_sub(1) as usize;
            (target_active * 90) / 100 + 1
        }
        GovernanceAction::RotateRootKey { .. } => {
            let guard_signed = if let Some(guard_key) = guard_key_opt {
                msg.signatures.iter().any(|sig| guard_key.verify(&action_bytes, sig).is_ok())
            } else {
                false
            };
            if !guard_signed {
                return Err(GovernanceError::RotateRequiresGuard);
            }
            (msg.council_size_at_proposal as usize * 95) / 100 + 1
        }
        GovernanceAction::RotateGuardKey { .. } | GovernanceAction::LockCouncil => {
            if let GovernanceAction::LockCouncil = &msg.action {
                if guard_key_opt.is_none() {
                    return Err(GovernanceError::MissingGuardKey);
                }
            }
            (msg.council_size_at_proposal as usize * 95) / 100 + 1
        }
        _ => return Err(GovernanceError::UnhandledThresholdMath),
    };

    if state.active_council.is_empty() {
        return Err(GovernanceError::EmptyCouncil);
    }

    if valid_council_sigs >= required_signatures {
        for signer in valid_signers {
            state.last_signature_timestamps
                .insert(signer, msg.timestamp_sec);
        }
        let wait_time = if let GovernanceAction::UpdateBinary { .. } = &msg.action {
            Some(crate::governance::logic::OTA_TIMELOCK_SECONDS)
        } else {
            None
        };
        Ok(state.execute_action(msg, current_time_sec, wait_time))
    } else {
        Err(GovernanceError::InsufficientSignatures)
    }
}
