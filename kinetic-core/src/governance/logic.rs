use std::collections::{HashSet, HashMap};
use ed25519_dalek::VerifyingKey;
use sha2::{Digest, Sha256};

use crate::error::GovernanceError;
use super::types::{
    GovernanceAction, GovernanceEffect, GovernanceState, Hash256, SignedGovernanceMessage,
};

#[cfg(not(test))]
pub const ROOT_PUBLIC_KEY_HEX: &str = "REPLACE_ME_OFFLINE_GENERATED_ED25519_ROOT";
#[cfg(test)]
pub const ROOT_PUBLIC_KEY_HEX: &str =
    "be907b4bac84fee5ce8811db2defc9bf0b2a2a2bbc3d54d8a2257ecd70441962";

#[cfg(not(test))]
pub const GUARD_PUBLIC_KEY_HEX: &str = "REPLACE_ME_OFFLINE_GENERATED_ED25519_GUARD";
#[cfg(test)]
pub const GUARD_PUBLIC_KEY_HEX: &str =
    "207a067892821e25d770f1fba0c47c11ff4b813e54162ece9eb839e076231ab6";

pub const MIN_ACTIVE_COUNCIL: usize = 7;
pub const MAX_COUNCIL_SIZE: usize = 21;
pub const MAX_AGE_SECONDS: u64 = 14 * 24 * 60 * 60;
pub const TIMELOCK_SECONDS: u64 = 30 * 24 * 60 * 60;
pub const ACTIVE_WINDOW_SECONDS: u64 = 30 * 24 * 60 * 60;
pub const AUTO_LOCK_SECONDS: u64 = 365 * 24 * 60 * 60;
pub const OTA_TIMELOCK_SECONDS: u64 = 48 * 60 * 60;
pub const MIN_ACTIVE_NAMES: u32 = 10_000;

pub fn validate_keys_initialized() -> Result<(), GovernanceError> {
    if ROOT_PUBLIC_KEY_HEX.contains("REPLACE_ME") {
        return Err(GovernanceError::MissingRootKey);
    }

    let dummy_state = GovernanceState::new(0);
    let _ = dummy_state.get_root_key()?;
    let _ = dummy_state.get_guard_key()?;

    Ok(())
}

impl GovernanceState {
    pub fn new(genesis_timestamp_sec: u64) -> Self {
        Self {
            genesis_timestamp_sec,
            mode: crate::governance::types::GovernanceMode::Founder,
            lock_timestamp_sec: None,
            active_council: Vec::new(),
            last_signature_timestamps: HashMap::new(),
            pending_timelocks: HashMap::new(),
            vetoed_hashes: HashSet::new(),
            pending_updates: HashMap::new(),
            partial_proposals: HashMap::new(),
            founder_premium_grants: 0,
            grace_period_start_sec: None,
        }
    }

    pub fn hash_action(msg: &SignedGovernanceMessage) -> Hash256 {
        let mut hasher = Sha256::new();
        hasher.update(msg.to_canonical_bytes());
        let result = hasher.finalize();
        let mut array = [0u8; 32];
        array.copy_from_slice(&result);
        array
    }

    pub fn merge_signatures(
        &mut self,
        incoming_msg: &SignedGovernanceMessage,
    ) -> SignedGovernanceMessage {
        let action_hash = Self::hash_action(incoming_msg);

        let mut msg_to_update = if let Some(existing) = self.partial_proposals.get(&action_hash) {
            existing.clone()
        } else {
            incoming_msg.clone()
        };

        let mut changed = false;
        for sig in &incoming_msg.signatures {
            if !msg_to_update.signatures.contains(sig) {
                msg_to_update.signatures.push(*sig);
                changed = true;
            }
        }

        if changed || !self.partial_proposals.contains_key(&action_hash) {
            self.partial_proposals
                .insert(action_hash, msg_to_update.clone());
        }

        msg_to_update
    }

    pub fn count_active_council(&self, current_time_sec: u64) -> usize {
        self.active_council
            .iter()
            .filter(|key| {
                if let Some(&last_sig_time) = self.last_signature_timestamps.get(key) {
                    current_time_sec.saturating_sub(last_sig_time) <= ACTIVE_WINDOW_SECONDS
                } else {
                    false
                }
            })
            .count()
    }

    pub fn get_root_key(&self) -> Result<VerifyingKey, GovernanceError> {
        let bytes =
            hex::decode(ROOT_PUBLIC_KEY_HEX).map_err(|_| GovernanceError::MissingRootKey)?;
        if bytes.len() != 32 {
            return Err(GovernanceError::KeyLengthMismatch);
        }
        VerifyingKey::try_from(bytes.as_slice()).map_err(|_| GovernanceError::KeyLengthMismatch)
    }

    pub fn get_guard_key(&self) -> Result<Option<VerifyingKey>, GovernanceError> {
        if GUARD_PUBLIC_KEY_HEX.contains("REPLACE_ME") {
            return Ok(None);
        }
        let bytes =
            hex::decode(GUARD_PUBLIC_KEY_HEX).map_err(|_| GovernanceError::MissingGuardKey)?;
        if bytes.len() != 32 {
            return Err(GovernanceError::KeyLengthMismatch);
        }
        let key = VerifyingKey::try_from(bytes.as_slice()).map_err(|_| GovernanceError::KeyLengthMismatch)?;
        Ok(Some(key))
    }

    pub fn verify_action(
        &mut self,
        msg: &SignedGovernanceMessage,
        current_time_sec: u64,
        active_names: u32,
    ) -> Result<Option<GovernanceEffect>, GovernanceError> {
        if current_time_sec.saturating_sub(msg.timestamp_sec) > MAX_AGE_SECONDS {
            return Err(GovernanceError::StaleProposal);
        }

        if let GovernanceAction::AppointMember { .. } | GovernanceAction::SelfAppointCouncilMember { .. } = &msg.action {
            if self.active_council.len() >= MAX_COUNCIL_SIZE {
                return Err(GovernanceError::CouncilAtCapacity);
            }
        }

        if let GovernanceAction::ExecuteTimelock { target_hash } = &msg.action {
            if let Some(&broadcast_time) = self.pending_timelocks.get(target_hash) {
                if current_time_sec >= broadcast_time + TIMELOCK_SECONDS {
                    return Ok(self.execute_action(msg, current_time_sec, None));
                } else {
                    return Err(GovernanceError::TimelockNotExpired);
                }
            } else if let Some(&(broadcast_time, wait_time, _)) = self.pending_updates.get(target_hash) {
                if current_time_sec >= broadcast_time + wait_time {
                    return Ok(self.execute_action(msg, current_time_sec, None));
                } else {
                    return Err(GovernanceError::OtaTimelockNotExpired);
                }
            } else {
                return Err(GovernanceError::NotPendingOrVetoed);
            }
        }

        let actual_active_count = self.count_active_council(current_time_sec);
        let guard_key_opt = self.get_guard_key()?;
        
        if self.mode == crate::governance::types::GovernanceMode::Founder {
            let instant_lock = actual_active_count >= MIN_ACTIVE_COUNCIL && guard_key_opt.is_some();
            let year_passed = current_time_sec >= self.genesis_timestamp_sec + AUTO_LOCK_SECONDS;
            let network_mature = active_names >= MIN_ACTIVE_NAMES;

            if instant_lock {
                self.mode = crate::governance::types::GovernanceMode::Council;
                self.lock_timestamp_sec = Some(current_time_sec);
                self.grace_period_start_sec = None; // clear grace period if it was active
            } else if year_passed && network_mature && self.grace_period_start_sec.is_none() {
                self.grace_period_start_sec = Some(current_time_sec);
            }

            if let Some(start_sec) = self.grace_period_start_sec {
                if current_time_sec >= start_sec + 30 * 24 * 60 * 60 {
                    // TODO: add rules after 13 months
                }
            }
        }

        let effective_active_count = std::cmp::max(actual_active_count, MIN_ACTIVE_COUNCIL);
        if msg.council_size_at_proposal < effective_active_count as u32 {
            return Err(GovernanceError::CouncilSizeMismatch);
        }

        match self.mode {
            crate::governance::types::GovernanceMode::Founder => crate::governance::founder::verify_action(self, msg, current_time_sec),
            crate::governance::types::GovernanceMode::Council => crate::governance::council::verify_action(self, msg, current_time_sec),
        }
    }

    pub fn execute_action(
        &mut self,
        msg: &SignedGovernanceMessage,
        current_time_sec: u64,
        wait_time: Option<u64>,
    ) -> Option<GovernanceEffect> {
        let mut effect = None;
        match &msg.action {
            GovernanceAction::AppointMember { key }
            | GovernanceAction::SelfAppointCouncilMember { candidate_key: key } => {
                if !self.active_council.contains(key) {
                    self.active_council.push(*key);
                }
            }
            GovernanceAction::RemoveCouncilMember { target_key } => {
                self.active_council.retain(|k| k != target_key);
                self.last_signature_timestamps.remove(target_key);
            }
            GovernanceAction::LockCouncil => {
                if self.mode == crate::governance::types::GovernanceMode::Founder {
                    self.mode = crate::governance::types::GovernanceMode::Council;
                    self.lock_timestamp_sec = Some(current_time_sec);
                }
            }
            GovernanceAction::UpdateBinary { hash, mirrors, .. } => {
                if let Some(wait_sec) = wait_time {
                    let action_hash = Self::hash_action(msg);
                    self.pending_updates
                        .insert(action_hash, (current_time_sec, wait_sec, mirrors.clone()));
                } else {
                    effect = Some(GovernanceEffect::TriggerOTA {
                        hash: *hash,
                        mirrors: mirrors.clone(),
                    });
                }
            }
            GovernanceAction::VetoUpdate { target_hash } => {
                self.pending_timelocks.remove(target_hash);
                self.pending_updates.remove(target_hash);
                self.vetoed_hashes.insert(*target_hash);
            }
            GovernanceAction::EmergencyReset { override_mode, .. } => {
                if *override_mode {
                    let action_hash = Self::hash_action(msg);
                    self.pending_timelocks.insert(action_hash, current_time_sec);
                } else {
                    self.mode = crate::governance::types::GovernanceMode::Founder;
                    self.active_council.clear();
                }
            }
            GovernanceAction::ExecuteTimelock { target_hash } => {
                self.pending_timelocks.remove(target_hash);
                if let Some((_, _, mirrors)) = self.pending_updates.remove(target_hash) {
                    effect = Some(GovernanceEffect::TriggerOTA {
                        hash: *target_hash,
                        mirrors,
                    });
                }
            }
            GovernanceAction::GrantPremiumName { name, target_pubkey } => {
                if self.mode == crate::governance::types::GovernanceMode::Founder {
                    self.founder_premium_grants += 1;
                }
                effect = Some(GovernanceEffect::PremiumNameGranted {
                    name: name.clone(),
                    target_pubkey: *target_pubkey,
                });
            }
            GovernanceAction::RevokePremiumName { name } => {
                effect = Some(GovernanceEffect::PremiumNameRevoked {
                    name: name.clone(),
                });
            }
            GovernanceAction::RotateRootKey { .. } | GovernanceAction::RotateGuardKey { .. } => {}
        }
        effect
    }

    pub fn check_timelocks(&mut self, current_time_sec: u64) -> Vec<GovernanceEffect> {
        let mut effects = Vec::new();
        let mut matured_hashes = Vec::new();

        for (hash, (broadcast_time, wait_time, mirrors)) in &self.pending_updates {
            if current_time_sec >= *broadcast_time + *wait_time {
                matured_hashes.push((*hash, mirrors.clone()));
            }
        }

        for (hash, mirrors) in matured_hashes {
            self.pending_updates.remove(&hash);
            effects.push(GovernanceEffect::TriggerOTA { hash, mirrors });
        }

        effects
    }
}

pub fn process_governance_message(
    state: &mut GovernanceState,
    msg: &SignedGovernanceMessage,
    active_names: u32,
) -> Result<Option<GovernanceEffect>, crate::error::GovernanceError> {
    let msg_to_update = state.merge_signatures(msg);
    let current_time_sec = web_time::SystemTime::now()
        .duration_since(web_time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    state.verify_action(&msg_to_update, current_time_sec, active_names)
}
