use ed25519_dalek::Verifier;
use std::collections::HashSet;

use crate::error::GovernanceError;
use crate::governance::types::{
    GovernanceAction, GovernanceEffect, GovernanceState, SignedGovernanceMessage,
};
use crate::traits::GovernanceEngine;

pub struct BicameralEngine;

impl GovernanceEngine for BicameralEngine {
    fn verify_action(
        &self,
        state: &mut GovernanceState,
        msg: &SignedGovernanceMessage,
        current_time_sec: u64,
    ) -> Result<Option<GovernanceEffect>, GovernanceError> {
        let actual_active_count = state.count_active_council(current_time_sec);
        let guard_key_opt = state.get_guard_key()?;

        if state.mode == crate::governance::types::GovernanceMode::Founder {
            let instant_lock = actual_active_count >= crate::governance::logic::MIN_ACTIVE_COUNCIL && guard_key_opt.is_some();
            let year_passed = current_time_sec >= state.genesis_timestamp_sec + crate::governance::logic::AUTO_LOCK_SECONDS;

            if instant_lock {
                state.mode = crate::governance::types::GovernanceMode::Council;
                state.lock_timestamp_sec = Some(current_time_sec);
                state.grace_period_start_sec = None;
            } else if year_passed && state.grace_period_start_sec.is_none() {
                state.grace_period_start_sec = Some(current_time_sec);
            }

            if let Some(start_sec) = state.grace_period_start_sec {
                if current_time_sec >= start_sec + 30 * 24 * 60 * 60 {
                    state.mode = crate::governance::types::GovernanceMode::Council;
                    state.lock_timestamp_sec = Some(current_time_sec);
                    state.grace_period_start_sec = None;
                }
            }
        }

        let effective_active_count = std::cmp::max(actual_active_count, crate::governance::logic::MIN_ACTIVE_COUNCIL);
        if msg.council_size_at_proposal < effective_active_count as u32 {
            return Err(GovernanceError::CouncilSizeMismatch);
        }

        match state.mode {
            crate::governance::types::GovernanceMode::Founder => {
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
                        let label = name
                            .strip_suffix(crate::constants::TLD_SUFFIX)
                            .unwrap_or(name);
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
                    return Ok(self.execute_action(state, msg, current_time_sec, wait_time));
                }

                // In Founder mode, only the Root key has authority to do things.
                Err(GovernanceError::InsufficientSignatures)
            }
            crate::governance::types::GovernanceMode::Council => {
                let guard_key_opt = state.get_guard_key()?;
                let action_bytes = msg.to_canonical_bytes();

                if let GovernanceAction::VetoUpdate { .. } = &msg.action {
                    if let Some(guard_key) = guard_key_opt {
                        if msg
                            .signatures
                            .iter()
                            .any(|sig| guard_key.verify(&action_bytes, sig).is_ok())
                        {
                            return Ok(self.execute_action(state, msg, current_time_sec, None));
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
                        msg.signatures
                            .iter()
                            .any(|sig| guard_key.verify(&action_bytes, sig).is_ok())
                    } else {
                        false
                    };

                    if !root_signed {
                        return Err(GovernanceError::EmergencyResetRequiresRoot);
                    }
                    if !*override_mode && !guard_signed {
                        return Err(GovernanceError::EmergencyResetRequiresGuard);
                    }

                    return Ok(self.execute_action(state, msg, current_time_sec, None));
                }

                if let GovernanceAction::GrantPremiumName { name, .. }
                | GovernanceAction::RevokePremiumName { name } = &msg.action
                {
                    let label = name
                        .strip_suffix(crate::constants::TLD_SUFFIX)
                        .unwrap_or(name);
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
                            msg.signatures
                                .iter()
                                .any(|sig| guard_key.verify(&action_bytes, sig).is_ok())
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
                        state
                            .last_signature_timestamps
                            .insert(signer, msg.timestamp_sec);
                    }
                    let wait_time = if let GovernanceAction::UpdateBinary { .. } = &msg.action {
                        Some(crate::governance::logic::OTA_TIMELOCK_SECONDS)
                    } else {
                        None
                    };
                    Ok(self.execute_action(state, msg, current_time_sec, wait_time))
                } else {
                    Err(GovernanceError::InsufficientSignatures)
                }
            }
        }
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
            GovernanceAction::AppointMember { key }
            | GovernanceAction::SelfAppointCouncilMember { candidate_key: key } => {
                if !state.active_council.contains(key) {
                    state.active_council.push(*key);
                }
            }
            GovernanceAction::RemoveCouncilMember { target_key } => {
                state.active_council.retain(|k| k != target_key);
                state.last_signature_timestamps.remove(target_key);
            }
            GovernanceAction::LockCouncil => {
                if state.mode == crate::governance::types::GovernanceMode::Founder {
                    state.mode = crate::governance::types::GovernanceMode::Council;
                    state.lock_timestamp_sec = Some(current_time_sec);
                }
            }
            GovernanceAction::UpdateBinary {
                manifest_hash,
                mirrors,
                ..
            } => {
                if let Some(wait_sec) = wait_time {
                    let action_hash = GovernanceState::hash_action(msg);
                    state.pending_updates
                        .insert(action_hash, (current_time_sec, wait_sec, mirrors.clone()));
                } else {
                    effect = Some(GovernanceEffect::TriggerOTA {
                        manifest_hash: *manifest_hash,
                        mirrors: mirrors.clone(),
                    });
                }
            }
            GovernanceAction::VetoUpdate { target_hash } => {
                state.pending_timelocks.remove(target_hash);
                state.pending_updates.remove(target_hash);
                state.vetoed_hashes.insert(*target_hash);
            }
            GovernanceAction::EmergencyReset { override_mode, .. } => {
                if *override_mode {
                    let action_hash = GovernanceState::hash_action(msg);
                    state.pending_timelocks.insert(action_hash, current_time_sec);
                } else {
                    state.mode = crate::governance::types::GovernanceMode::Founder;
                    state.active_council.clear();
                }
            }
            GovernanceAction::ExecuteTimelock { target_hash } => {
                state.pending_timelocks.remove(target_hash);

                if let Some(original) = state.partial_proposals.get(target_hash) {
                    if let GovernanceAction::EmergencyReset { override_mode, .. } = &original.action
                    {
                        if *override_mode {
                            state.mode = crate::governance::types::GovernanceMode::Founder;
                            state.active_council.clear();
                        }
                    }
                }

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
                if state.mode == crate::governance::types::GovernanceMode::Founder {
                    state.founder_premium_grants += 1;
                }
                effect = Some(GovernanceEffect::PremiumNameGranted {
                    name: name.clone(),
                    target_pubkey: *target_pubkey,
                });
            }
            GovernanceAction::RevokePremiumName { name } => {
                effect = Some(GovernanceEffect::PremiumNameRevoked { name: name.clone() });
            }
            GovernanceAction::RotateRootKey { .. } | GovernanceAction::RotateGuardKey { .. } => {}
        }
        effect
    }
}
