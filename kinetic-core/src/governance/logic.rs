use std::collections::{HashSet, HashMap};
use ed25519_dalek::{Verifier, VerifyingKey};
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
pub const MAX_AGE_SECONDS: u64 = 14 * 24 * 60 * 60;
pub const TIMELOCK_SECONDS: u64 = 30 * 24 * 60 * 60;
pub const ACTIVE_WINDOW_SECONDS: u64 = 30 * 24 * 60 * 60;
pub const AUTO_LOCK_SECONDS: u64 = 365 * 24 * 60 * 60;

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
            is_locked: false,
            lock_timestamp_sec: None,
            active_council: Vec::new(),
            last_signature_timestamps: HashMap::new(),
            pending_timelocks: HashMap::new(),
            vetoed_hashes: HashSet::new(),
            pending_updates: HashMap::new(),
            partial_proposals: HashMap::new(),
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
    ) -> Result<Option<GovernanceEffect>, GovernanceError> {
        if current_time_sec.saturating_sub(msg.timestamp_sec) > MAX_AGE_SECONDS {
            return Err(GovernanceError::StaleProposal);
        }

        if let GovernanceAction::ExecuteTimelock { target_hash } = &msg.action {
            if let Some(&broadcast_time) = self.pending_timelocks.get(target_hash) {
                if current_time_sec >= broadcast_time + TIMELOCK_SECONDS {
                    return Ok(self.execute_action(msg, current_time_sec, false));
                } else {
                    return Err(GovernanceError::TimelockNotExpired);
                }
            } else if let Some(&(broadcast_time, _)) = self.pending_updates.get(target_hash) {
                if current_time_sec >= broadcast_time + 86400 {
                    return Ok(self.execute_action(msg, current_time_sec, false));
                } else {
                    return Err(GovernanceError::OtaTimelockNotExpired);
                }
            } else {
                return Err(GovernanceError::NotPendingOrVetoed);
            }
        }

        let actual_active_count = self.count_active_council(current_time_sec);
        let guard_key_opt = self.get_guard_key()?;
        
        if !self.is_locked
            && current_time_sec >= self.genesis_timestamp_sec + AUTO_LOCK_SECONDS
            && actual_active_count >= MIN_ACTIVE_COUNCIL
            && guard_key_opt.is_some()
        {
            self.is_locked = true;
            self.lock_timestamp_sec = Some(self.genesis_timestamp_sec + AUTO_LOCK_SECONDS);
        }

        let effective_active_count = std::cmp::max(actual_active_count, MIN_ACTIVE_COUNCIL);
        if msg.council_size_at_proposal < effective_active_count as u32 {
            return Err(GovernanceError::CouncilSizeMismatch);
        }

        let root_key = self.get_root_key()?;
        let action_bytes = msg.to_canonical_bytes();

        if let GovernanceAction::VetoUpdate { .. } = &msg.action {
            if let Some(guard_key) = guard_key_opt {
                if msg.signatures.iter().any(|sig| guard_key.verify(&action_bytes, sig).is_ok()) {
                    return Ok(self.execute_action(msg, current_time_sec, true));
                }
            }
            return Err(GovernanceError::InvalidGuardSignature);
        }

        let is_phase_1 = match self.lock_timestamp_sec {
            Some(lock_time) => msg.timestamp_sec < lock_time,
            None => !self.is_locked,
        };

        if is_phase_1
            && msg
                .signatures
                .iter()
                .any(|sig| root_key.verify(&action_bytes, sig).is_ok())
        {
            if let GovernanceAction::LockCouncil = &msg.action {
                if guard_key_opt.is_none() {
                    return Err(GovernanceError::MissingGuardKey);
                }
            }
            return Ok(self.execute_action(msg, current_time_sec, true));
        }

        if let GovernanceAction::EmergencyReset { override_mode, .. } = &msg.action {
            let action_hash = Self::hash_action(msg);
            if self.vetoed_hashes.contains(&action_hash) {
                return Err(GovernanceError::EmergencyResetVetoed);
            }
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
                if guard_key_opt.is_some() || !is_phase_1 {
                    return Err(GovernanceError::EmergencyResetRequiresGuard);
                }
            }

            return Ok(self.execute_action(msg, current_time_sec, true));
        }

        let mut counted_members = HashSet::new();
        let mut valid_signers = HashSet::new();
        for sig in &msg.signatures {
            for (idx, member) in self.active_council.iter().enumerate() {
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
            GovernanceAction::SelfAppointCouncilMember { .. } => {
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
                    if guard_key_opt.is_some() || !is_phase_1 {
                        return Err(GovernanceError::RotateRequiresGuard);
                    }
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

        if self.active_council.is_empty() {
            return Err(GovernanceError::EmptyCouncil);
        }

        if valid_council_sigs >= required_signatures {
            for signer in valid_signers {
                self.last_signature_timestamps
                    .insert(signer, msg.timestamp_sec);
            }
            Ok(self.execute_action(msg, current_time_sec, false))
        } else {
            Err(GovernanceError::InsufficientSignatures)
        }
    }

    fn execute_action(
        &mut self,
        msg: &SignedGovernanceMessage,
        current_time_sec: u64,
        is_instant: bool,
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
                if !self.is_locked {
                    self.is_locked = true;
                    self.lock_timestamp_sec = Some(current_time_sec);
                }
            }
            GovernanceAction::UpdateBinary { hash, mirrors, .. } => {
                if is_instant {
                    effect = Some(GovernanceEffect::TriggerOTA {
                        hash: *hash,
                        mirrors: mirrors.clone(),
                    });
                } else {
                    let action_hash = Self::hash_action(msg);
                    self.pending_updates
                        .insert(action_hash, (current_time_sec, mirrors.clone()));
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
                }
            }
            GovernanceAction::ExecuteTimelock { target_hash } => {
                self.pending_timelocks.remove(target_hash);
                if let Some((_, mirrors)) = self.pending_updates.remove(target_hash) {
                    effect = Some(GovernanceEffect::TriggerOTA {
                        hash: *target_hash,
                        mirrors,
                    });
                }
            }
            GovernanceAction::RotateRootKey { .. } | GovernanceAction::RotateGuardKey { .. } => {}
        }
        effect
    }

    pub fn check_timelocks(&mut self, current_time_sec: u64) -> Vec<GovernanceEffect> {
        let mut effects = Vec::new();
        let mut matured_hashes = Vec::new();

        for (hash, (broadcast_time, mirrors)) in &self.pending_updates {
            if current_time_sec >= *broadcast_time + 86400 {
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
) -> Result<Option<GovernanceEffect>, crate::error::GovernanceError> {
    let msg_to_update = state.merge_signatures(msg);
    let current_time_sec = web_time::SystemTime::now()
        .duration_since(web_time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    state.verify_action(&msg_to_update, current_time_sec)
}
