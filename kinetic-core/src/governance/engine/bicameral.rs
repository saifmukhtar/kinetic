//! Two-phase Bicameral governance engine driver (Founder bootstrap phase -> Council phase).

use std::collections::HashSet;

use crate::error::GovernanceError;
use crate::governance::types::{
    GovernanceAction, GovernanceEffect, GovernanceState, SignedGovernanceMessage,
};
use crate::traits::GovernanceEngine;

/// Default two-phase network governance engine driver.
pub struct BicameralEngine;

impl GovernanceEngine for BicameralEngine {
    /// Verifies proposals against Founder single-signer or Council supermajority voting rules based on current phase mode.
    ///
    /// # Errors
    ///
    /// - Returns [`GovernanceError::FounderPremiumLimitReached`] if Founder attempts to grant more than 5 premium names.
    /// - Returns [`GovernanceError::InvalidGuardSignature`] if a Guard veto signature fails verification.
    /// - Returns [`GovernanceError::RotateRequiresGuard`] if Root key rotation lacks Guard co-signature.
    /// - Returns [`GovernanceError::InsufficientSignatures`] if signatures do not meet phase threshold bounds.
    /// - Returns [`GovernanceError::StaleProposal`] if the proposal timestamp is older than [`crate::constants::MAX_AGE_SECONDS`].
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

        let actual_active_count = state.count_active_council(current_time_sec);
        let guard_key_opt = state.get_guard_key()?;

        if state.mode == crate::governance::types::GovernanceMode::Founder {
            let instant_lock = actual_active_count >= crate::constants::MIN_ACTIVE_COUNCIL
                && guard_key_opt.is_some();

            if instant_lock {
                state.mode = crate::governance::types::GovernanceMode::Council;
                state.lock_timestamp_sec = Some(current_time_sec);
                state.grace_period_start_sec = None;
            }
        }

        let effective_active_count =
            std::cmp::max(actual_active_count, crate::constants::MIN_ACTIVE_COUNCIL);
        if msg.council_size_at_proposal < effective_active_count as u32 {
            return Err(GovernanceError::CouncilSizeMismatch);
        }

        match state.mode {
            crate::governance::types::GovernanceMode::Founder => {
                if let GovernanceAction::RevokePremiumName { .. } = &msg.action {
                    return Err(GovernanceError::RevokeRequiresCouncilMode);
                }

                let root_key = state.get_root_key()?;
                let guard_key_opt = state.get_guard_key()?;
                let action_bytes = msg.to_canonical_bytes();

                let root_signed = msg.signatures.iter().any(|sig| {
                    crate::governance::types::verify_signature(&root_key, &action_bytes, sig)
                });

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
                        Some(1 * 24 * 60 * 60) // 1 day
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
                        if msg.signatures.iter().any(|sig| {
                            crate::governance::types::verify_signature(
                                &guard_key,
                                &action_bytes,
                                sig,
                            )
                        }) {
                            return Ok(self.execute_action(state, msg, current_time_sec, None));
                        }
                    }
                    return Err(GovernanceError::InvalidGuardSignature);
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
                        if !counted_members.contains(&idx)
                            && crate::governance::types::verify_signature(
                                member,
                                &action_bytes,
                                sig,
                            )
                        {
                            counted_members.insert(idx);
                            valid_signers.insert(member.clone());
                            break;
                        }
                    }
                }

                let valid_council_sigs = counted_members.len();

                let required_signatures = match &msg.action {
                    GovernanceAction::AppointMember { .. }
                    | GovernanceAction::UpdateBinary { .. } => {
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
                            msg.signatures.iter().any(|sig| {
                                crate::governance::types::verify_signature(
                                    &guard_key,
                                    &action_bytes,
                                    sig,
                                )
                            })
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
                        Some(crate::constants::OTA_TIMELOCK_SECONDS)
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
                    state.active_council.push(key.clone());
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
                if state.mode == crate::governance::types::GovernanceMode::Founder {
                    state.founder_premium_grants += 1;
                }
                effect = Some(GovernanceEffect::PremiumNameGranted {
                    name: name.clone(),
                    target_pubkey: target_pubkey.clone(),
                });
            }
            GovernanceAction::RevokePremiumName { name } => {
                effect = Some(GovernanceEffect::PremiumNameRevoked { name: name.clone() });
            }
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
