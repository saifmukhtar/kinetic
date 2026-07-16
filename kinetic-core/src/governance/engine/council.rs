use ed25519_dalek::Verifier;
use std::collections::HashSet;

use crate::error::GovernanceError;
use crate::governance::types::{
    GovernanceAction, GovernanceEffect, GovernanceState, SignedGovernanceMessage,
};
use crate::traits::GovernanceEngine;

pub struct CouncilEngine;

impl GovernanceEngine for CouncilEngine {
    fn verify_action(
        &self,
        state: &mut GovernanceState,
        msg: &SignedGovernanceMessage,
        current_time_sec: u64,
    ) -> Result<Option<GovernanceEffect>, GovernanceError> {
        let actual_active_count = state.count_active_council(current_time_sec);
        let effective_active_count =
            std::cmp::max(actual_active_count, crate::constants::MIN_ACTIVE_COUNCIL);

        if msg.council_size_at_proposal < effective_active_count as u32 {
            return Err(GovernanceError::CouncilSizeMismatch);
        }

        let action_bytes = msg.to_canonical_bytes();

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
            GovernanceAction::LockCouncil => (msg.council_size_at_proposal as usize * 95) / 100 + 1,
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
                // Irrelevant in pure Council mode, but harmless to allow.
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
            GovernanceAction::ExecuteTimelock { target_hash } => {
                state.pending_timelocks.remove(target_hash);

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
                    target_pubkey: *target_pubkey,
                });
            }
            GovernanceAction::RevokePremiumName { name } => {
                effect = Some(GovernanceEffect::PremiumNameRevoked { name: name.clone() });
            }
            GovernanceAction::RotateRootKey { .. }
            | GovernanceAction::RotateGuardKey { .. }
            | GovernanceAction::VetoUpdate { .. }
            | GovernanceAction::EmergencyReset { .. } => {}
        }
        effect
    }
}
