use crate::error::GovernanceError;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use lazy_static::lazy_static;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

/// 32-byte hash type for proposed updates
pub type Hash256 = [u8; 32];

// =========================================================================
// TRUST ANCHORS
// =========================================================================

/// The Master Key (Root Key) belonging to the Founder.
/// Panics at startup if unconfigured.
#[cfg(not(test))]
pub const ROOT_PUBLIC_KEY_HEX: &str = "REPLACE_ME_OFFLINE_GENERATED_ED25519_ROOT";

/// The Master Key (Root Key) belonging to the Founder.
/// (Test Configuration)
#[cfg(test)]
pub const ROOT_PUBLIC_KEY_HEX: &str =
    "be907b4bac84fee5ce8811db2defc9bf0b2a2a2bbc3d54d8a2257ecd70441962";

/// The Guard Key (Veto Key) belonging to the Founder.
/// Panics at startup if unconfigured.
#[cfg(not(test))]
pub const GUARD_PUBLIC_KEY_HEX: &str = "REPLACE_ME_OFFLINE_GENERATED_ED25519_GUARD";

/// The Guard Key (Veto Key) belonging to the Founder.
/// (Test Configuration)
#[cfg(test)]
pub const GUARD_PUBLIC_KEY_HEX: &str =
    "207a067892821e25d770f1fba0c47c11ff4b813e54162ece9eb839e076231ab6";

/// Minimum number of council members required to form an active quorum.
pub const MIN_ACTIVE_COUNCIL: usize = 7;
/// Maximum age in seconds for a signed governance proposal to be considered valid.
pub const MAX_AGE_SECONDS: u64 = 14 * 24 * 60 * 60; // 14 days
/// The mandatory timelock period before certain governance actions (e.g. overrides) can execute.
pub const TIMELOCK_SECONDS: u64 = 30 * 24 * 60 * 60; // 30 days
/// Rolling window in seconds to consider a council member "active" based on their last signature.
pub const ACTIVE_WINDOW_SECONDS: u64 = 30 * 24 * 60 * 60; // 30 days
/// Time since genesis after which the council auto-locks into Phase 2 (removing Founder bypass).
pub const AUTO_LOCK_SECONDS: u64 = 365 * 24 * 60 * 60; // 12 months

lazy_static! {
    /// The global singleton holding the current node's view of the governance state.
    pub static ref GLOBAL_GOVERNANCE_STATE: Mutex<GovernanceState> =
        Mutex::new(GovernanceState::new(
            web_time::SystemTime::now()
                .duration_since(web_time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        ));
}

// =========================================================================
// TYPES
// =========================================================================

/// Defines all possible actions the Bicameral Council can vote on.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum GovernanceAction {
    /// Appoint a new standard council member.
    AppointMember {
        /// Ed25519 public key of the new member.
        key: VerifyingKey,
    },
    /// Initiate a network-wide binary update (OTA).
    UpdateBinary {
        /// Expected SHA256 hash of the new binary.
        hash: Hash256,
        /// Monotonically increasing version counter.
        version_nonce: u64,
        /// List of HTTPS mirrors serving the binary.
        mirrors: Vec<String>,
    },
    /// Manually transition governance to Phase 2 (locked).
    LockCouncil,
    /// Veto a pending OTA update (Guard key only).
    VetoUpdate {
        /// The hash of the OTA update to veto.
        target_hash: Hash256,
    },
    /// Replace the root Master Key.
    RotateRootKey {
        /// The new Ed25519 root public key.
        new_key: VerifyingKey,
    },
    /// Replace the Guard Veto Key.
    RotateGuardKey {
        /// The new Ed25519 guard public key.
        new_key: VerifyingKey,
    },
    /// Propose oneself as a new council member (requires high consensus).
    SelfAppointCouncilMember {
        /// The candidate's Ed25519 public key.
        candidate_key: VerifyingKey,
    },
    /// Eject an existing council member.
    RemoveCouncilMember {
        /// The public key to remove.
        target_key: VerifyingKey,
    },
    /// Emergency protocol reset (e.g. compromised keys).
    EmergencyReset {
        /// The new root key.
        new_root: VerifyingKey,
        /// The new guard key.
        new_guard: VerifyingKey,
        /// Whether this override bypasses normal timelocks.
        override_mode: bool,
    },
    /// Execute a timelocked action whose delay has expired.
    ExecuteTimelock {
        /// Hash of the previously approved action.
        target_hash: Hash256,
    }, // Public execution trigger
}

/// Side-effects returned by the governance engine after processing a message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GovernanceEffect {
    /// Instructs the node to download and apply an OTA update immediately.
    TriggerOTA {
        /// Hash of the verified binary to apply.
        hash: Hash256,
        /// List of URLs serving the update.
        mirrors: Vec<String>,
    },
}

/// A GovernanceAction accompanied by signatures establishing its validity.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SignedGovernanceMessage {
    /// The action being proposed or ratified.
    pub action: GovernanceAction,
    /// The number of council members at the time this message was signed (prevents denominator attacks).
    pub council_size_at_proposal: u32,
    /// Unix timestamp (seconds) when the proposal was created.
    pub timestamp_sec: u64,
    /// Collected Ed25519 signatures from council members or trust anchors.
    pub signatures: Vec<Signature>,
}

/// The authoritative state of the Bicameral Governance Council.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GovernanceState {
    /// Timestamp of network genesis.
    pub genesis_timestamp_sec: u64,
    /// Whether the council has transitioned to Phase 2 (removing Founder bypass).
    pub is_locked: bool,
    /// When the transition to Phase 2 occurred.
    pub lock_timestamp_sec: Option<u64>,
    /// List of public keys of active council members.
    pub active_council: Vec<VerifyingKey>,
    /// Tracks the last time each key signed an action to measure activity.
    pub last_signature_timestamps: HashMap<VerifyingKey, u64>,
    /// Maps action hashes to the timestamp they were approved (waiting for execution).
    pub pending_timelocks: HashMap<Hash256, u64>,
    /// Hashes of actions that the Guard Key has permanently vetoed.
    pub vetoed_hashes: HashSet<Hash256>,
    /// Pending OTA updates (timestamp of approval, mirror URLs).
    pub pending_updates: HashMap<Hash256, (u64, Vec<String>)>, // timestamp, mirrors
    /// Proposals that are currently collecting signatures but haven't reached quorum.
    pub partial_proposals: HashMap<Hash256, SignedGovernanceMessage>,
}

/// Validates that both the Root and Guard keys have been replaced from their default 'REPLACE_ME' values.
pub fn validate_keys_initialized() -> Result<(), GovernanceError> {
    if ROOT_PUBLIC_KEY_HEX.contains("REPLACE_ME") {
        return Err(GovernanceError::MissingRootKey);
    }
    if GUARD_PUBLIC_KEY_HEX.contains("REPLACE_ME") {
        return Err(GovernanceError::MissingGuardKey);
    }

    // Validate they decode properly
    let dummy_state = GovernanceState::new(0);
    let _ = dummy_state.get_root_key()?;
    let _ = dummy_state.get_guard_key()?;

    Ok(())
}

// =========================================================================
// SERIALIZATION
// =========================================================================

impl SignedGovernanceMessage {
    /// Canonical byte serialization strictly for signing.
    /// `[action_tag: u8] [action_data] [council_size_at_proposal: u32_be] [timestamp_sec: u64_be]`
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        match &self.action {
            GovernanceAction::AppointMember { key } => {
                buf.push(0x00);
                buf.extend_from_slice(key.as_bytes());
            }
            GovernanceAction::UpdateBinary {
                hash,
                version_nonce,
                mirrors,
            } => {
                buf.push(0x01);
                buf.extend_from_slice(hash);
                buf.extend_from_slice(&version_nonce.to_be_bytes());
                buf.extend_from_slice(&(mirrors.len() as u32).to_be_bytes());
                for mirror in mirrors {
                    let bytes = mirror.as_bytes();
                    buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
                    buf.extend_from_slice(bytes);
                }
            }
            GovernanceAction::LockCouncil => {
                buf.push(0x02);
            }
            GovernanceAction::VetoUpdate { target_hash } => {
                buf.push(0x03);
                buf.extend_from_slice(target_hash);
            }
            GovernanceAction::RotateRootKey { new_key } => {
                buf.push(0x04);
                buf.extend_from_slice(new_key.as_bytes());
            }
            GovernanceAction::RotateGuardKey { new_key } => {
                buf.push(0x05);
                buf.extend_from_slice(new_key.as_bytes());
            }
            GovernanceAction::SelfAppointCouncilMember { candidate_key } => {
                buf.push(0x06);
                buf.extend_from_slice(candidate_key.as_bytes());
            }
            GovernanceAction::RemoveCouncilMember { target_key } => {
                buf.push(0x07);
                buf.extend_from_slice(target_key.as_bytes());
            }
            GovernanceAction::EmergencyReset {
                new_root,
                new_guard,
                override_mode,
            } => {
                buf.push(0x08);
                buf.extend_from_slice(new_root.as_bytes());
                buf.extend_from_slice(new_guard.as_bytes());
                buf.push(if *override_mode { 1 } else { 0 });
            }
            GovernanceAction::ExecuteTimelock { target_hash } => {
                buf.push(0x09);
                buf.extend_from_slice(target_hash);
            }
        }

        buf.extend_from_slice(&self.council_size_at_proposal.to_be_bytes());
        buf.extend_from_slice(&self.timestamp_sec.to_be_bytes());
        buf
    }
}

// =========================================================================
// LOGIC
// =========================================================================

impl GovernanceState {
    /// Serializes the state to disk atomically using a `.tmp` file.
    pub fn save_to_disk(&self, path: &std::path::Path) -> std::io::Result<()> {
        let temp_path = path.with_extension("tmp");
        let file = std::fs::File::create(&temp_path)?;
        bincode::serialize_into(file, self).map_err(std::io::Error::other)?;
        std::fs::rename(temp_path, path)?;
        Ok(())
    }

    /// Loads the state from disk, or falls back to a fresh state if the file is missing/corrupt.
    pub fn load_from_disk(path: &std::path::Path) -> Self {
        if let Ok(file) = std::fs::File::open(path) {
            if let Ok(state) = bincode::deserialize_from(file) {
                return state;
            }
        }
        // Fallback to fresh state
        Self::new(
            web_time::SystemTime::now()
                .duration_since(web_time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        )
    }

    /// Initializes a fresh governance state.
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

    /// Computes the deterministic hash of a Governance Message (for timelock tracking)
    pub fn hash_action(msg: &SignedGovernanceMessage) -> Hash256 {
        let mut hasher = Sha256::new();
        hasher.update(msg.to_canonical_bytes());
        let result = hasher.finalize();
        let mut array = [0u8; 32];
        array.copy_from_slice(&result);
        array
    }

    /// Accumulates signatures from a partial proposal
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

    /// Count members who have signed anything within the ACTIVE_WINDOW_SECONDS
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

    /// Parses and returns the root master key.
    pub fn get_root_key(&self) -> Result<VerifyingKey, GovernanceError> {
        let bytes =
            hex::decode(ROOT_PUBLIC_KEY_HEX).map_err(|_| GovernanceError::MissingRootKey)?;
        if bytes.len() != 32 {
            return Err(GovernanceError::KeyLengthMismatch);
        }
        VerifyingKey::try_from(bytes.as_slice()).map_err(|_| GovernanceError::KeyLengthMismatch)
    }

    /// Parses and returns the guard veto key.
    pub fn get_guard_key(&self) -> Result<VerifyingKey, GovernanceError> {
        let bytes =
            hex::decode(GUARD_PUBLIC_KEY_HEX).map_err(|_| GovernanceError::MissingGuardKey)?;
        if bytes.len() != 32 {
            return Err(GovernanceError::KeyLengthMismatch);
        }
        VerifyingKey::try_from(bytes.as_slice()).map_err(|_| GovernanceError::KeyLengthMismatch)
    }

    /// Validates a signed governance message against the Bicameral Rule Book.
    pub fn verify_action(
        &mut self,
        msg: &SignedGovernanceMessage,
        current_time_sec: u64,
    ) -> Result<Option<GovernanceEffect>, GovernanceError> {
        // 1. STALENESS CHECK
        if current_time_sec.saturating_sub(msg.timestamp_sec) > MAX_AGE_SECONDS {
            return Err(GovernanceError::StaleProposal);
        }

        // 2. TIMELOCK EXECUTION (Public trigger, no signatures required)
        if let GovernanceAction::ExecuteTimelock { target_hash } = &msg.action {
            if let Some(&broadcast_time) = self.pending_timelocks.get(target_hash) {
                if current_time_sec >= broadcast_time + TIMELOCK_SECONDS {
                    // We execute it (assuming no Guard Veto cancelled it previously)
                    return Ok(self.execute_action(msg, current_time_sec, false));
                } else {
                    return Err(GovernanceError::TimelockNotExpired);
                }
            } else if let Some(&(broadcast_time, _)) = self.pending_updates.get(target_hash) {
                // Update Timelock (24 hours = 86400 seconds)
                if current_time_sec >= broadcast_time + 86400 {
                    return Ok(self.execute_action(msg, current_time_sec, false));
                } else {
                    return Err(GovernanceError::OtaTimelockNotExpired);
                }
            } else {
                return Err(GovernanceError::NotPendingOrVetoed);
            }
        }

        // 3. AUTO-LOCK TRANSITION CHECK
        // If 12 months passed since genesis AND >= 7 active members, we auto-lock Phase 1 away.
        let actual_active_count = self.count_active_council(current_time_sec);
        if !self.is_locked
            && current_time_sec >= self.genesis_timestamp_sec + AUTO_LOCK_SECONDS
            && actual_active_count >= MIN_ACTIVE_COUNCIL
        {
            self.is_locked = true;
            self.lock_timestamp_sec = Some(self.genesis_timestamp_sec + AUTO_LOCK_SECONDS);
        }

        // 4. DENOMINATOR VALIDATION
        let effective_active_count = std::cmp::max(actual_active_count, MIN_ACTIVE_COUNCIL);
        if msg.council_size_at_proposal < effective_active_count as u32 {
            return Err(GovernanceError::CouncilSizeMismatch);
        }

        let root_key = self.get_root_key()?;
        let guard_key = self.get_guard_key()?;
        let action_bytes = msg.to_canonical_bytes();

        // 5. GUARD VETO
        if let GovernanceAction::VetoUpdate { .. } = &msg.action {
            if msg
                .signatures
                .iter()
                .any(|sig| guard_key.verify(&action_bytes, sig).is_ok())
            {
                return Ok(self.execute_action(msg, current_time_sec, true));
            }
            return Err(GovernanceError::InvalidGuardSignature);
        }

        // Determine if this message is evaluated under Phase 1 or Phase 2 rules
        let is_phase_1 = match self.lock_timestamp_sec {
            Some(lock_time) => msg.timestamp_sec < lock_time,
            None => !self.is_locked,
        };

        // 6. PHASE 1 ROOT BYPASS
        if is_phase_1
            && msg
                .signatures
                .iter()
                .any(|sig| root_key.verify(&action_bytes, sig).is_ok())
        {
            return Ok(self.execute_action(msg, current_time_sec, true));
        }

        // 7. EMERGENCY RESET
        if let GovernanceAction::EmergencyReset { override_mode, .. } = &msg.action {
            let action_hash = Self::hash_action(msg);
            if self.vetoed_hashes.contains(&action_hash) {
                return Err(GovernanceError::EmergencyResetVetoed);
            }
            let root_signed = msg
                .signatures
                .iter()
                .any(|sig| root_key.verify(&action_bytes, sig).is_ok());
            let guard_signed = msg
                .signatures
                .iter()
                .any(|sig| guard_key.verify(&action_bytes, sig).is_ok());

            if !root_signed {
                return Err(GovernanceError::EmergencyResetRequiresRoot);
            }
            if !*override_mode && !guard_signed {
                return Err(GovernanceError::EmergencyResetRequiresGuard);
            }

            return Ok(self.execute_action(msg, current_time_sec, true));
        }

        // 8. COUNCIL MULTI-SIG
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
                let target_active = msg.council_size_at_proposal.saturating_sub(1) as usize; // Exclude target
                (target_active * 90) / 100 + 1
            }
            GovernanceAction::RotateRootKey { .. } => {
                if !msg
                    .signatures
                    .iter()
                    .any(|sig| guard_key.verify(&action_bytes, sig).is_ok())
                {
                    return Err(GovernanceError::RotateRequiresGuard);
                }
                (msg.council_size_at_proposal as usize * 95) / 100 + 1
            }
            GovernanceAction::RotateGuardKey { .. } | GovernanceAction::LockCouncil => {
                (msg.council_size_at_proposal as usize * 95) / 100 + 1
            }
            _ => return Err(GovernanceError::UnhandledThresholdMath),
        };

        if self.active_council.is_empty() {
            return Err(GovernanceError::EmptyCouncil);
        }

        if valid_council_sigs >= required_signatures {
            // Apply signature timestamps only for successfully verified actions
            for signer in valid_signers {
                self.last_signature_timestamps
                    .insert(signer, msg.timestamp_sec);
            }
            Ok(self.execute_action(msg, current_time_sec, false))
        } else {
            Err(GovernanceError::InsufficientSignatures)
        }
    }

    /// Executes the validated action, mutating the state.
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
                // Cancel pending timelocks if they exist
                self.pending_timelocks.remove(target_hash);
                self.pending_updates.remove(target_hash);
                // Persist veto state so it survives reboots
                self.vetoed_hashes.insert(*target_hash);
            }
            GovernanceAction::EmergencyReset { override_mode, .. } => {
                if *override_mode {
                    // Start the 30-day timelock
                    let action_hash = Self::hash_action(msg);
                    self.pending_timelocks.insert(action_hash, current_time_sec);
                } else {
                    // Instant reset logic executed by higher-level protocol
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
                // The actual reset logic executed by higher-level protocol
            }
            GovernanceAction::RotateRootKey { .. } | GovernanceAction::RotateGuardKey { .. } => {
                // To be implemented via consensus network logic.
                // Currently, ROOT and GUARD are constants so they require binary updates,
                // but this represents the intent that can be read by clients.
                // RotateRootKey and RotateGuardKey are parsed but not executed
                // until the network daemon implements dynamic key management.
            }
        }
        effect
    }

    /// Automatically scans and executes mature pending updates.
    /// Should be called periodically (e.g., every minute) by the node.
    pub fn check_timelocks(&mut self, current_time_sec: u64) -> Vec<GovernanceEffect> {
        let mut effects = Vec::new();
        let mut matured_hashes = Vec::new();

        // Check 24-hour OTA Timelocks
        for (hash, (broadcast_time, mirrors)) in &self.pending_updates {
            if current_time_sec >= *broadcast_time + 86400 {
                matured_hashes.push((*hash, mirrors.clone()));
            }
        }

        // Trigger effects and clean up
        for (hash, mirrors) in matured_hashes {
            self.pending_updates.remove(&hash);
            effects.push(GovernanceEffect::TriggerOTA { hash, mirrors });
        }

        // Note: Generic pending_timelocks (30-day logic) omitted for brevity
        // as they require external network state triggers, but could be added here.

        effects
    }
}

/// Helper to merge signatures into the global state and process the message in one step.
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

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    fn get_root_sk() -> SigningKey {
        let bytes = hex::decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
            .unwrap();
        SigningKey::from_bytes(bytes.as_slice().try_into().unwrap())
    }

    fn get_guard_sk() -> SigningKey {
        let bytes = hex::decode("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
            .unwrap();
        SigningKey::from_bytes(bytes.as_slice().try_into().unwrap())
    }

    // Helper to generate a random keypair and return its pubkey
    fn generate_key(seed: u8) -> (SigningKey, VerifyingKey) {
        let bytes = [seed; 32];
        let signing_key = SigningKey::from_bytes(&bytes);
        let verifying_key = signing_key.verifying_key();
        (signing_key, verifying_key)
    }

    // Helper to sign an action
    fn sign_action(msg: &SignedGovernanceMessage, signer: &SigningKey) -> Signature {
        let serialized = msg.to_canonical_bytes();
        signer.sign(&serialized)
    }

    #[test]
    fn test_phase1_root_key_bypass() {
        let root_sk = get_root_sk();
        let current_time = web_time::SystemTime::now()
            .duration_since(web_time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut state = GovernanceState::new(current_time);

        let action = GovernanceAction::UpdateBinary {
            hash: [1u8; 32],
            version_nonce: 1,
            mirrors: vec!["http://test.com".to_string()],
        };

        let mut msg = SignedGovernanceMessage {
            action,
            council_size_at_proposal: 7,
            timestamp_sec: current_time,
            signatures: vec![],
        };

        let sig = sign_action(&msg, &root_sk);
        msg.signatures.push(sig);

        let effect = process_governance_message(&mut state, &msg).unwrap();
        // Phase 1 root key bypass triggers instantly
        assert!(matches!(effect, Some(GovernanceEffect::TriggerOTA { .. })));
    }

    #[test]
    fn test_council_supermajority_ratification() {
        let current_time = web_time::SystemTime::now()
            .duration_since(web_time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut state = GovernanceState::new(current_time);

        let (c1_sk, c1_pk) = generate_key(1);
        let (c2_sk, c2_pk) = generate_key(2);
        let (c3_sk, c3_pk) = generate_key(3);

        state.active_council.push(c1_pk);
        state.active_council.push(c2_pk);
        state.active_council.push(c3_pk);
        let mut council = vec![(c1_sk, c1_pk), (c2_sk, c2_pk), (c3_sk, c3_pk)];
        for i in 0..4 {
            let (sk, pk) = generate_key(4 + i as u8);
            state.active_council.push(pk);
            council.push((sk, pk));
        }

        for pk in &state.active_council {
            state.last_signature_timestamps.insert(*pk, current_time);
        }

        state.is_locked = true;
        state.lock_timestamp_sec = Some(current_time - 100);

        let action = GovernanceAction::UpdateBinary {
            hash: [2u8; 32],
            version_nonce: 2,
            mirrors: vec!["http://test2.com".to_string()],
        };

        let mut msg1 = SignedGovernanceMessage {
            action: action.clone(),
            council_size_at_proposal: 7,
            timestamp_sec: current_time,
            signatures: vec![],
        };

        msg1.signatures.push(sign_action(&msg1, &council[0].0));
        let err = process_governance_message(&mut state, &msg1).unwrap_err();
        assert!(matches!(
            err,
            crate::error::GovernanceError::InsufficientSignatures
        ));

        let mut msg_full = SignedGovernanceMessage {
            action: action.clone(),
            council_size_at_proposal: 7,
            timestamp_sec: current_time,
            signatures: vec![],
        };
        for item in council.iter().take(5) {
            msg_full
                .signatures
                .push(sign_action(&msg_full, &item.0));
        }

        let action_hash = GovernanceState::hash_action(&msg_full);

        let effect = process_governance_message(&mut state, &msg_full).unwrap();
        assert!(effect.is_none());
        // Should be pending in timelock indexed by action hash
        assert!(state.pending_updates.contains_key(&action_hash));
    }

    #[test]
    fn test_guard_key_veto() {
        let guard_sk = get_guard_sk();
        let current_time = web_time::SystemTime::now()
            .duration_since(web_time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut state = GovernanceState::new(current_time);

        // Manually insert a pending update
        let action_hash = [3u8; 32];
        state
            .pending_updates
            .insert(action_hash, (current_time, vec![]));

        let veto_action = GovernanceAction::VetoUpdate {
            target_hash: action_hash,
        };
        let mut veto_msg = SignedGovernanceMessage {
            action: veto_action,
            council_size_at_proposal: 7,
            timestamp_sec: current_time,
            signatures: vec![],
        };
        veto_msg.signatures.push(sign_action(&veto_msg, &guard_sk));

        let effect = process_governance_message(&mut state, &veto_msg).unwrap();
        assert!(effect.is_none());

        assert!(!state.pending_updates.contains_key(&action_hash));
        assert!(state.vetoed_hashes.contains(&action_hash));
    }
}
