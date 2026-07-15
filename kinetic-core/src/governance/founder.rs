use ed25519_dalek::Verifier;

use crate::error::GovernanceError;
use super::types::{GovernanceAction, GovernanceEffect, GovernanceState, SignedGovernanceMessage};

pub fn verify_action(
    state: &mut GovernanceState,
    msg: &SignedGovernanceMessage,
    current_time_sec: u64,
) -> Result<Option<GovernanceEffect>, GovernanceError> {
    if let GovernanceAction::EmergencyReset { .. } = &msg.action {
        return Err(GovernanceError::EmergencyResetInPhase1);
    }
    if let GovernanceAction::RevokePremiumName { .. } = &msg.action {
        return Err(GovernanceError::RevokeRequiresCouncilMode);
    }

    let root_key = state.get_root_key()?;
    let guard_key_opt = state.get_guard_key()?;
    let action_bytes = msg.to_canonical_bytes();

    let root_signed = msg
        .signatures
        .iter()
        .any(|sig| root_key.verify(&action_bytes, sig).is_ok());

    if root_signed {
        if let GovernanceAction::LockCouncil = &msg.action {
            if guard_key_opt.is_none() {
                return Err(GovernanceError::MissingGuardKey);
            }
        }
        if let GovernanceAction::GrantPremiumName { name, .. } = &msg.action {
            let label = name.strip_suffix(crate::constants::TLD_SUFFIX).unwrap_or(name);
            if label.len() != 1 {
                return Err(GovernanceError::InvalidPremiumNameLength);
            }
            if state.founder_premium_grants >= 5 {
                return Err(GovernanceError::FounderPremiumLimitReached);
            }
        }
        let wait_time = if let GovernanceAction::UpdateBinary { .. } = &msg.action {
            Some(3 * 24 * 60 * 60) // 3 days
        } else {
            None
        };
        return Ok(state.execute_action(msg, current_time_sec, wait_time));
    }

    // In Founder mode, only the Root key has authority to do things.
    Err(GovernanceError::InsufficientSignatures)
}
