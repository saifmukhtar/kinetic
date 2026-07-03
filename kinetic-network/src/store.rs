use libp2p::kad::store::RecordStore;
use libp2p::{kad, PeerId};
use std::collections::HashMap;
use std::sync::Arc;

use kinetic_core::traits::StorageEngine;
use kinetic_storage::SledStorage;

use crate::error::KineticStoreError;

/// Finding 13 (Critical): Verify a HostRoutingRecord's signature and timestamp freshness.
/// This lives in kinetic-network (not kinetic-core) because it requires the libp2p dependency
/// to extract the Ed25519 public key from the PeerId multihash.
fn verify_host_routing_record(
    record: &kinetic_core::types::HostRoutingRecord,
) -> Result<(), KineticStoreError> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    // Enforce timestamp freshness — reject records older than 10 minutes.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| KineticStoreError::InvalidHostRouteSignature)?
        .as_secs();
    if now.saturating_sub(record.timestamp) > 600 {
        tracing::warn!(
            "HostRoutingRecord for {} is stale ({} seconds old)",
            record.host_id,
            now.saturating_sub(record.timestamp)
        );
        return Err(KineticStoreError::InvalidHostRouteSignature);
    }

    // Parse the host_id as a libp2p PeerId and extract its public key.
    let host_peer_id = record
        .host_id
        .parse::<libp2p::PeerId>()
        .map_err(|_| KineticStoreError::InvalidPublicKey)?;

    // Extract the Ed25519 public key bytes from the PeerId multihash.
    // libp2p Ed25519 PeerIds encode the 32-byte public key in their multihash payload.
    let pubkey_bytes: [u8; 32] = match host_peer_id.as_ref().digest() {
        bytes if bytes.len() >= 36 => {
            // Multihash format: <varint code> <varint length> <payload>
            // For identity multihash, the payload starts at byte 2 and contains
            // the protobuf-encoded public key. The last 32 bytes are the raw ed25519 key.
            let payload = &bytes[bytes.len() - 32..];
            let mut arr = [0u8; 32];
            arr.copy_from_slice(payload);
            arr
        }
        _ => return Err(KineticStoreError::InvalidPublicKey),
    };

    let verifying_key = VerifyingKey::from_bytes(&pubkey_bytes)
        .map_err(|_| KineticStoreError::InvalidPublicKey)?;

    let sig = Signature::from_slice(&record.signature)
        .map_err(|_| KineticStoreError::MalformedSignature)?;

    let signable = record.signable_bytes();
    verifying_key
        .verify(&signable, &sig)
        .map_err(|_| KineticStoreError::InvalidHostRouteSignature)
}

pub const KRS_REVEAL_PREFIX: &str = "krs_reveal:";
pub const KRS_HB_PREFIX: &str = "krs_hb:";
pub const KRS_HIB_PREFIX: &str = "krs_hib:";
pub const KRS_COMMIT_PREFIX: &str = "krs_cmt:";

use lru::LruCache;
use std::num::NonZeroUsize;

pub struct KineticRecordStore {
    inner: kad::store::MemoryStore,
    pub storage: Arc<SledStorage>,
    pub reveals_by_name: LruCache<String, kinetic_core::types::Reveal>,
    pub last_heartbeats_by_name: HashMap<String, u64>,
    pub hibernations_by_name: HashMap<String, (u64, u64)>, // (drand_round, iterations)
    pub commitments_by_hash: HashMap<[u8; 32], u64>,
    pub accepted_reveals_timestamps: std::collections::VecDeque<std::time::Instant>,
    pub current_drand_round: u64,
}

impl KineticRecordStore {
    pub fn new(local_peer_id: PeerId, storage: Arc<SledStorage>, initial_drand_round: u64) -> Self {
        let mut reveals_by_name = LruCache::new(NonZeroUsize::new(10_000).unwrap());
        let mut last_heartbeats_by_name = HashMap::new();
        let mut hibernations_by_name = HashMap::new();

        // Restore state from sled
        if let Ok(iter) = storage.scan_prefix(KRS_REVEAL_PREFIX.as_bytes()) {
            for (key_bytes, val_bytes) in iter {
                let key_str = String::from_utf8_lossy(&key_bytes).to_string();
                let name = key_str.trim_start_matches(KRS_REVEAL_PREFIX).to_string();
                if let Ok(reveal) =
                    serde_json::from_slice::<kinetic_core::types::Reveal>(&val_bytes)
                {
                    tracing::info!("[KRS restore] Reveal for {}", name);
                    reveals_by_name.put(name, reveal);
                }
            }
        }

        if let Ok(iter) = storage.scan_prefix(KRS_HB_PREFIX.as_bytes()) {
            for (key_bytes, val_bytes) in iter {
                let key_str = String::from_utf8_lossy(&key_bytes).to_string();
                let name = key_str.trim_start_matches(KRS_HB_PREFIX).to_string();
                if val_bytes.len() == 8 {
                    let round = u64::from_be_bytes(val_bytes[..8].try_into().unwrap_or([0u8; 8]));
                    tracing::info!("[KRS restore] Heartbeat round {} for {}", round, name);
                    last_heartbeats_by_name.insert(name, round);
                }
            }
        }

        if let Ok(iter) = storage.scan_prefix(KRS_HIB_PREFIX.as_bytes()) {
            for (key_bytes, val_bytes) in iter {
                let key_str = String::from_utf8_lossy(&key_bytes).to_string();
                let name = key_str.trim_start_matches(KRS_HIB_PREFIX).to_string();
                if val_bytes.len() == 16 {
                    let round = u64::from_be_bytes(val_bytes[0..8].try_into().unwrap_or([0u8; 8]));
                    let iters = u64::from_be_bytes(val_bytes[8..16].try_into().unwrap_or([0u8; 8]));
                    tracing::info!(
                        "[KRS restore] Hibernation round {} (iters: {}) for {}",
                        round,
                        iters,
                        name
                    );
                    hibernations_by_name.insert(name, (round, iters));
                } else if val_bytes.len() == 8 {
                    let round = u64::from_be_bytes(val_bytes[..8].try_into().unwrap_or([0u8; 8]));
                    hibernations_by_name.insert(name, (round, 500_000_000));
                }
            }
        }

        let mut commitments_by_hash = HashMap::new();
        if let Ok(iter) = storage.scan_prefix(KRS_COMMIT_PREFIX.as_bytes()) {
            for (key_bytes, val_bytes) in iter {
                if key_bytes.len() > KRS_COMMIT_PREFIX.len() {
                    let hash_hex = String::from_utf8_lossy(&key_bytes[KRS_COMMIT_PREFIX.len()..]).to_string();
                    if let Ok(hash) = hex::decode(&hash_hex) {
                        if hash.len() == 32 && val_bytes.len() == 8 {
                            let mut hash_arr = [0u8; 32];
                            hash_arr.copy_from_slice(&hash);
                            let round = u64::from_be_bytes(val_bytes[..8].try_into().unwrap_or([0u8; 8]));
                            commitments_by_hash.insert(hash_arr, round);
                        }
                    }
                }
            }
        }

        let mut inner = kad::store::MemoryStore::new(local_peer_id);

        for (name, reveal) in reveals_by_name.iter() {
            if let Ok(val) = serde_json::to_vec(reveal) {
                let keys = kinetic_core::types::derive_storage_keys(name);
                for key_bytes in keys {
                    let k = kad::RecordKey::new(&key_bytes);
                    let record = kad::Record::new(k, val.clone());
                    let _ = inner.put(record);
                }
            }
        }

        Self {
            inner,
            storage,
            reveals_by_name,
            last_heartbeats_by_name,
            hibernations_by_name,
            commitments_by_hash,
            accepted_reveals_timestamps: std::collections::VecDeque::new(),
            current_drand_round: initial_drand_round,
        }
    }

    fn handle_reveal(
        &mut self,
        reveal: &kinetic_core::types::Reveal,
    ) -> Result<(), kad::store::Error> {
        // Finding 3: Use the shared constant instead of a hardcoded magic number.
        if self.current_drand_round.saturating_sub(reveal.drand_pulse)
            > kinetic_core::types::RESQUARING_EPOCH_ROUNDS
        {
            let age = self.current_drand_round.saturating_sub(reveal.drand_pulse);
            let err = KineticStoreError::VdfExpired { age };
            tracing::warn!(
                error_code = "KIN-STORE-001",
                name = %reveal.name,
                age = age,
                severity = ?err.severity(),
                "Rejecting Reveal: {}", err
            );
            return Err(err.into());
        }

        if !self.verify_reveal_internal(reveal) {
            let err = KineticStoreError::InvalidVdf;
            tracing::warn!(
                error_code = "KIN-STORE-002",
                name = %reveal.name,
                severity = ?err.severity(),
                "Rejecting Reveal: {}", err
            );
            return Err(err.into());
        }

        if let Some(existing_reveal) = self.reveals_by_name.get(&reveal.name) {
            if existing_reveal.pubkey != reveal.pubkey {
                let consensus_math = kinetic_core::consensus_math::ConsensusParams::default();
                let last_hb_round = self
                    .last_heartbeats_by_name
                    .get(&reveal.name)
                    .copied()
                    .unwrap_or(reveal.drand_pulse);

                if let Some(&(hib_round, hib_iters)) = self.hibernations_by_name.get(&reveal.name) {
                    let hib_age = self.current_drand_round.saturating_sub(hib_round);
                    let exemption_rounds = consensus_math.hibernation_exemption_rounds(hib_iters);
                    if hib_age < exemption_rounds {
                        let err = KineticStoreError::Hibernating;
                        tracing::warn!(
                            error_code = "KIN-STORE-003",
                            name = %reveal.name,
                            hib_age = hib_age,
                            exemption_rounds = exemption_rounds,
                            severity = ?err.severity(),
                            "Rejecting Steal Reveal: {}", err
                        );
                        return Err(err.into());
                    }
                }

                let hb_age = self.current_drand_round.saturating_sub(last_hb_round);
                let base_diff = consensus_math.required_iterations(
                    &reveal.name,
                    reveal.drand_pulse,
                    &reveal.pubkey,
                );
                let steal_threshold = consensus_math.steal_difficulty(base_diff, hb_age);

                // Case 121: Deterministic Tie-Breaking
                if reveal.iterations == existing_reveal.iterations && hb_age < 100 {
                    if reveal.pubkey > existing_reveal.pubkey {
                        let err = KineticStoreError::TieBroken;
                        tracing::warn!(
                            error_code = "KIN-STORE-004",
                            name = %reveal.name,
                            severity = ?err.severity(),
                            "Rejecting Steal Reveal: {}", err
                        );
                        return Err(err.into());
                    } else {
                        tracing::info!("Valid Steal Reveal for {}! Tie-break won!", reveal.name);
                    }
                } else if reveal.iterations < steal_threshold {
                    let err = KineticStoreError::InsufficientIterations;
                    tracing::warn!(
                        error_code = "KIN-STORE-005",
                        name = %reveal.name,
                        iterations = reveal.iterations,
                        required = steal_threshold,
                        hb_age = hb_age,
                        severity = ?err.severity(),
                        "Rejecting Steal Reveal: {}", err
                    );
                    return Err(err.into());
                } else {
                    tracing::info!("Valid Steal Reveal for {}! Overwriting previous owner (idle for {} rounds).", reveal.name, hb_age);
                }
            }
        }

        self.reveals_by_name
            .put(reveal.name.clone(), reveal.clone());
        let reveal_key = format!("{}{}", KRS_REVEAL_PREFIX, reveal.name);
        if let Ok(bytes) = serde_json::to_vec(&reveal) {
            let _ = self.storage.put(reveal_key.as_bytes(), &bytes);
        }

        let now = std::time::Instant::now();
        self.accepted_reveals_timestamps.push_back(now);
        while let Some(t) = self.accepted_reveals_timestamps.front() {
            if now.duration_since(*t) > std::time::Duration::from_secs(3600) {
                self.accepted_reveals_timestamps.pop_front();
            } else {
                break;
            }
        }
        if self.accepted_reveals_timestamps.len() > 100 {
            tracing::warn!("ALERT: High registration rate ({} valid reveals accepted in the last hour). VDF difficulty parameters may need revision.", self.accepted_reveals_timestamps.len());
        }

        let current_round = std::cmp::max(self.current_drand_round, reveal.drand_pulse);
        self.last_heartbeats_by_name
            .insert(reveal.name.clone(), current_round);
        let hb_key = format!("{}{}", KRS_HB_PREFIX, reveal.name);
        let _ = self
            .storage
            .put(hb_key.as_bytes(), &current_round.to_be_bytes());

        Ok(())
    }

    fn handle_hibernation(
        &mut self,
        hibernation: &kinetic_core::types::Hibernation,
    ) -> Result<(), kad::store::Error> {
        let existing_reveal = match self.reveals_by_name.get(&hibernation.name) {
            Some(r) => r,
            None => {
                let err = KineticStoreError::RevealNotFound;
                tracing::warn!(
                    error_code = "KIN-STORE-006",
                    name = %hibernation.name,
                    severity = ?err.severity(),
                    "Rejecting Hibernation: {}", err
                );
                return Err(err.into());
            }
        };

        let signable = hibernation.signable_bytes();
        let pubkey = ed25519_dalek::VerifyingKey::try_from(existing_reveal.pubkey.as_slice())
            .map_err(|_| {
                let err = KineticStoreError::InvalidPublicKey;
                tracing::warn!(
                    error_code = "KIN-STORE-007",
                    name = %hibernation.name,
                    severity = ?err.severity(),
                    "Rejecting Hibernation: {}", err
                );
                kad::store::Error::ValueTooLarge
            })?;
        let sig = ed25519_dalek::Signature::from_slice(&hibernation.signature).map_err(|_| {
            let err = KineticStoreError::MalformedSignature;
            tracing::warn!(
                error_code = "KIN-STORE-008",
                name = %hibernation.name,
                severity = ?err.severity(),
                "Rejecting Hibernation: {}", err
            );
            kad::store::Error::ValueTooLarge
        })?;

        use ed25519_dalek::Verifier;
        if pubkey.verify(&signable, &sig).is_err() {
            let err = KineticStoreError::InvalidSignature;
            tracing::warn!(
                error_code = "KIN-STORE-009",
                name = %hibernation.name,
                severity = ?err.severity(),
                "Rejecting Hibernation: {}", err
            );
            return Err(err.into());
        }

        use kinetic_core::traits::VdfEngine;
        use kinetic_vdf::ChiaVdfEngine;
        use sha2::{Digest as _, Sha256};

        let challenge_bytes =
            hex::decode(&hibernation.drand_randomness).unwrap_or_else(|_| vec![0u8; 32]);
        let mut hasher = Sha256::new();
        hasher.update(hibernation.name.as_bytes());
        hasher.update(hibernation.salt);
        hasher.update(&challenge_bytes);
        hasher.update(&existing_reveal.pubkey);
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&hasher.finalize());
        let challenge = kinetic_core::types::Commitment { hash };

        let engine = ChiaVdfEngine::new();
        match engine.verify(&challenge, &hibernation.vdf_proof, hibernation.iterations) {
            Ok(true) => {
                let consensus_math = kinetic_core::consensus_math::ConsensusParams::default();
                let exemption_rounds =
                    consensus_math.hibernation_exemption_rounds(hibernation.iterations);
                tracing::info!(
                    "Accepted valid Hibernation VDF for {}. Exempt from heartbeats for {} rounds.",
                    hibernation.name,
                    exemption_rounds
                );

                let current_round = self.current_drand_round;
                self.hibernations_by_name.insert(
                    hibernation.name.clone(),
                    (current_round, hibernation.iterations),
                );
                let hib_key = format!("{}{}", KRS_HIB_PREFIX, hibernation.name);
                let mut val = Vec::new();
                val.extend_from_slice(&current_round.to_be_bytes());
                val.extend_from_slice(&hibernation.iterations.to_be_bytes());
                let _ = self.storage.put(hib_key.as_bytes(), &val);
                Ok(())
            }
            Ok(false) => {
                let err = KineticStoreError::InvalidVdf;
                tracing::warn!(
                    error_code = "KIN-STORE-010",
                    name = %hibernation.name,
                    iterations = hibernation.iterations,
                    severity = ?err.severity(),
                    "Hibernation rejected: {}", err
                );
                Err(err.into())
            }
            Err(e) => {
                let err = KineticStoreError::VdfEngineError(e.to_string());
                tracing::warn!(
                    error_code = "KIN-STORE-011",
                    name = %hibernation.name,
                    severity = ?err.severity(),
                    "Hibernation rejected: {}", err
                );
                Err(err.into())
            }
        }
    }

    fn handle_heartbeat(
        &mut self,
        heartbeat: &kinetic_core::types::Heartbeat,
    ) -> Result<(), kad::store::Error> {
        let existing_reveal = match self.reveals_by_name.get(&heartbeat.name) {
            Some(r) => r,
            None => {
                let err = KineticStoreError::RevealNotFound;
                tracing::warn!(
                    error_code = "KIN-STORE-012",
                    name = %heartbeat.name,
                    severity = ?err.severity(),
                    "Rejecting Heartbeat: {}", err
                );
                return Err(err.into());
            }
        };

        let signable = heartbeat.signable_bytes();
        let pubkey = ed25519_dalek::VerifyingKey::try_from(existing_reveal.pubkey.as_slice())
            .map_err(|_| {
                let err = KineticStoreError::InvalidPublicKey;
                tracing::warn!(
                    error_code = "KIN-STORE-013",
                    name = %heartbeat.name,
                    severity = ?err.severity(),
                    "Rejecting Heartbeat: {}", err
                );
                kad::store::Error::ValueTooLarge
            })?;
        let sig = ed25519_dalek::Signature::from_slice(&heartbeat.signature).map_err(|_| {
            let err = KineticStoreError::MalformedSignature;
            tracing::warn!(
                error_code = "KIN-STORE-014",
                name = %heartbeat.name,
                severity = ?err.severity(),
                "Rejecting Heartbeat: {}", err
            );
            kad::store::Error::ValueTooLarge
        })?;

        use ed25519_dalek::Verifier;
        if pubkey.verify(&signable, &sig).is_err() {
            let err = KineticStoreError::InvalidSignature;
            tracing::warn!(
                error_code = "KIN-STORE-015",
                name = %heartbeat.name,
                severity = ?err.severity(),
                "Rejecting Heartbeat: {}", err
            );
            return Err(err.into());
        }

        if heartbeat.latest_drand_pulse > self.current_drand_round + 2 {
            let err = KineticStoreError::StaleHeartbeat;
            tracing::warn!(
                error_code = "KIN-STORE-021",
                name = %heartbeat.name,
                received_pulse = heartbeat.latest_drand_pulse,
                current_pulse = self.current_drand_round,
                severity = ?err.severity(),
                "Rejecting Heartbeat: future-dated"
            );
            return Err(err.into());
        }

        // Finding 8: Monotonicity check — reject a heartbeat that would regress the
        // liveness clock, preventing replay attacks that accelerate steal windows.
        let existing_pulse = self
            .last_heartbeats_by_name
            .get(&heartbeat.name)
            .copied()
            .unwrap_or(0);
        if heartbeat.latest_drand_pulse <= existing_pulse {
            let err = KineticStoreError::StaleHeartbeat;
            tracing::warn!(
                error_code = "KIN-STORE-020",
                name = %heartbeat.name,
                received_pulse = heartbeat.latest_drand_pulse,
                existing_pulse = existing_pulse,
                severity = ?err.severity(),
                "Rejecting Heartbeat: {}", err
            );
            return Err(err.into());
        }

        self.last_heartbeats_by_name
            .insert(heartbeat.name.clone(), heartbeat.latest_drand_pulse);
        let hb_key = format!("{}{}", KRS_HB_PREFIX, heartbeat.name);
        let _ = self.storage.put(
            hb_key.as_bytes(),
            &heartbeat.latest_drand_pulse.to_be_bytes(),
        );
        Ok(())
    }

    pub fn prune(&mut self) {
        let current_round = self.current_drand_round;
        let mut expired_commitments = Vec::new();
        for (&hash, &round) in &self.commitments_by_hash {
            if current_round.saturating_sub(round) >= 100 {
                expired_commitments.push(hash);
            }
        }
        for hash in expired_commitments {
            self.commitments_by_hash.remove(&hash);
            let key = format!("{}{}", KRS_COMMIT_PREFIX, hex::encode(hash));
            let _ = self.storage.delete(key.as_bytes());
        }

        let consensus_math = kinetic_core::consensus_math::ConsensusParams::default();
        let max_age_rounds = kinetic_core::types::RESQUARING_EPOCH_ROUNDS; // Finding 3: use shared constant
        let idle_timeout = (14 * 24 * 3600) / 30; // 14 days in 30s rounds

        let mut expired_names = Vec::new();

        for (name, reveal) in &self.reveals_by_name {
            // --- Genesis Infinity Lock ---
            if let Some(genesis_pk) = kinetic_core::consensus_math::ConsensusParams::GENESIS_PUBKEY {
                let normalized_name = kinetic_core::types::normalize_name(name);
                let label_without_tld = normalized_name
                    .strip_suffix(".kin")
                    .unwrap_or(&normalized_name);
                if kinetic_core::consensus_math::ConsensusParams::GENESIS_ALLOWLIST.contains(&label_without_tld) {
                    if reveal.pubkey.as_slice() == genesis_pk {
                        tracing::debug!("Genesis Infinity Lock active for {}. Bypassing pruning.", name);
                        continue;
                    }
                }
            }
            // -----------------------------

            let age = current_round.saturating_sub(reveal.drand_pulse);
            if age > max_age_rounds {
                expired_names.push(name.clone());
                continue;
            }

            let last_hb = self.last_heartbeats_by_name.get(name).copied().unwrap_or(reveal.drand_pulse);
            let hb_age = current_round.saturating_sub(last_hb);

            let mut exemption_rounds = 0;
            if let Some(&(hib_round, hib_iters)) = self.hibernations_by_name.get(name) {
                let hib_age = current_round.saturating_sub(hib_round);
                let granted_exemption = consensus_math.hibernation_exemption_rounds(hib_iters);
                if hib_age < granted_exemption {
                    exemption_rounds = granted_exemption - hib_age;
                }
            }

            if hb_age > idle_timeout + exemption_rounds {
                expired_names.push(name.clone());
            }
        }

        for name in expired_names {
            tracing::info!("Pruning expired/idle name: {}", name);
            self.reveals_by_name.pop(&name);
            self.last_heartbeats_by_name.remove(&name);
            self.hibernations_by_name.remove(&name);

            let _ = self
                .storage
                .delete(format!("{}{}", KRS_REVEAL_PREFIX, name).as_bytes());
            let _ = self
                .storage
                .delete(format!("{}{}", KRS_HB_PREFIX, name).as_bytes());
            let _ = self
                .storage
                .delete(format!("{}{}", KRS_HIB_PREFIX, name).as_bytes());

            let keys = kinetic_core::types::derive_storage_keys(&name);
            for key_bytes in keys {
                let k = kad::RecordKey::new(&key_bytes);
                let sled_key = format!("kad_record:{}", hex::encode(k.as_ref()));
                let _ = self.storage.delete(sled_key.as_bytes());
            }

            let hb_keys = kinetic_core::types::derive_heartbeat_keys(&name);
            for key_bytes in hb_keys {
                let k = kad::RecordKey::new(&key_bytes);
                let sled_key = format!("kad_record:{}", hex::encode(k.as_ref()));
                let _ = self.storage.delete(sled_key.as_bytes());
            }
        }
    }

    fn verify_reveal_internal(&self, reveal: &kinetic_core::types::Reveal) -> bool {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        use kinetic_core::traits::VdfEngine;
        use kinetic_core::types::Commitment;
        use kinetic_vdf::ChiaVdfEngine;
        use sha2::{Digest, Sha256};

        let signable = reveal.signable_bytes();
        let pubkey = match VerifyingKey::try_from(reveal.pubkey.as_slice()) {
            Ok(k) => k,
            Err(_) => return false,
        };
        let signature = match Signature::from_slice(&reveal.signature) {
            Ok(s) => s,
            Err(_) => return false,
        };

        if pubkey.verify(&signable, &signature).is_err() {
            tracing::warn!("Rejecting Kademlia Reveal: Invalid Ed25519 Signature");
            return false;
        }

        let engine = ChiaVdfEngine::new();
        let challenge_bytes =
            hex::decode(&reveal.drand_randomness).unwrap_or_else(|_| vec![0u8; 32]);
        let mut hasher = Sha256::new();
        hasher.update(reveal.name.as_bytes());
        hasher.update(reveal.salt);
        hasher.update(&challenge_bytes);
        hasher.update(&reveal.pubkey);
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&hasher.finalize());
        let challenge = Commitment { hash };

        if let Some(&commit_round) = self.commitments_by_hash.get(&hash) {
            if self.current_drand_round.saturating_sub(commit_round) < 10 {
                tracing::warn!(
                    "Rejecting Reveal for {}: Commitment is too recent (age < 10 rounds)",
                    reveal.name
                );
                return false;
            }
            tracing::info!(
                "Commitment matched for Reveal of {} (committed around round {})",
                reveal.name,
                commit_round
            );
        } else {
            tracing::warn!(
                "Rejecting Reveal for {}: No prior Commitment found in DHT!",
                reveal.name
            );
            return false;
        }

        let consensus_math = kinetic_core::consensus_math::ConsensusParams::default();
        let required_iterations =
            consensus_math.required_iterations(&reveal.name, reveal.drand_pulse, &reveal.pubkey);

        if reveal.iterations < required_iterations {
            tracing::warn!(
                "Rejecting Kademlia Reveal: VDF iterations ({}) below required minimum ({})",
                reveal.iterations,
                required_iterations
            );
            return false;
        }

        match engine.verify(&challenge, &reveal.vdf_proof, reveal.iterations) {
            Ok(true) => true,
            _ => {
                tracing::warn!("Rejecting Kademlia Reveal: Invalid VDF Proof");
                false
            }
        }
    }
}

impl kad::store::RecordStore for KineticRecordStore {
    type RecordsIter<'a> = <kad::store::MemoryStore as kad::store::RecordStore>::RecordsIter<'a>;
    type ProvidedIter<'a> = <kad::store::MemoryStore as kad::store::RecordStore>::ProvidedIter<'a>;

    fn get(&self, k: &kad::RecordKey) -> Option<std::borrow::Cow<'_, kad::Record>> {
        if let Some(record) = self.inner.get(k) {
            return Some(record);
        }

        let sled_key = format!("kad_record:{}", hex::encode(k.as_ref()));
        if let Ok(Some(bytes)) = self.storage.get(sled_key.as_bytes()) {
            let record = kad::Record::new(k.clone(), bytes.to_vec());
            return Some(std::borrow::Cow::Owned(record));
        }

        None
    }

    fn put(&mut self, r: kad::Record) -> kad::store::Result<()> {
        tracing::info!("KineticRecordStore::put called for key: {:?}", r.key);

        if r.value.len() > 16 * 1024 {
            let err = KineticStoreError::PayloadTooLarge;
            tracing::warn!(
                error_code = "KIN-STORE-016",
                size = r.value.len(),
                severity = ?err.severity(),
                "Rejecting Kademlia record: {}", err
            );
            return Err(err.into());
        }

        if let Ok(commitment) = serde_json::from_slice::<kinetic_core::types::Commitment>(&r.value)
        {
            tracing::info!("KineticRecordStore::put parsed Commitment");
            self.commitments_by_hash
                .insert(commitment.hash, self.current_drand_round);
            let key = format!("{}{}", KRS_COMMIT_PREFIX, hex::encode(commitment.hash));
            let _ = self.storage.put(key.as_bytes(), &self.current_drand_round.to_be_bytes());
            return self.inner.put(r); // Commitments do not need permanent Sled caching (but we put them temporarily)
        } else if let Ok(reveal) = serde_json::from_slice::<kinetic_core::types::Reveal>(&r.value) {
            tracing::info!("KineticRecordStore::put parsed Reveal for {}", reveal.name);
            self.handle_reveal(&reveal)?;
        } else if let Ok(hibernation) =
            serde_json::from_slice::<kinetic_core::types::Hibernation>(&r.value)
        {
            tracing::info!(
                "KineticRecordStore::put parsed Hibernation for {}",
                hibernation.name
            );
            self.handle_hibernation(&hibernation)?;
        } else if let Ok(heartbeat) =
            serde_json::from_slice::<kinetic_core::types::Heartbeat>(&r.value)
        {
            tracing::info!(
                "KineticRecordStore::put parsed Heartbeat for {}",
                heartbeat.name
            );
            self.handle_heartbeat(&heartbeat)?;
        } else if let Ok(kid_doc) = serde_json::from_slice::<kinetic_kid::KidDocument>(&r.value) {
            if kid_doc.verify().is_ok() {
                tracing::info!(
                    "KineticRecordStore::put accepted valid KID Document for {}",
                    kid_doc.kid.as_str()
                );
            } else {
                let err = KineticStoreError::InvalidKidSignature;
                tracing::warn!(
                    error_code = "KIN-STORE-017",
                    severity = ?err.severity(),
                    "Rejecting KID Document: {}", err
                );
                return Err(err.into());
            }
        } else if let Ok(manifest) =
            serde_json::from_slice::<kinetic_kid::CapabilityManifest>(&r.value)
        {
            if manifest.verify_pow() {
                tracing::info!(
                    "KineticRecordStore::put accepted Capability Manifest for {} (PoW valid)",
                    manifest.kid.as_str()
                );
            } else {
                let err = KineticStoreError::InvalidManifestPoW;
                tracing::warn!(
                    error_code = "KIN-STORE-018",
                    severity = ?err.severity(),
                    "Rejecting Capability Manifest: {}", err
                );
                return Err(err.into());
            }
        } else if let Ok(host_route) =
            serde_json::from_slice::<kinetic_core::types::HostRoutingRecord>(&r.value)
        {
            // Finding 13 (Critical): Verify the signature on HostRoutingRecord before accepting.
            // Previously this branch did NO verification, allowing any peer to redirect
            // all proxy traffic for any .kin domain to an attacker-controlled PeerId.
            match verify_host_routing_record(&host_route) {
                Ok(()) => {
                    tracing::info!(
                        "KineticRecordStore::put accepted verified HostRoutingRecord for {}",
                        host_route.host_id
                    );
                }
                Err(err) => {
                    tracing::warn!(
                        error_code = "KIN-STORE-021",
                        host_id = %host_route.host_id,
                        severity = ?err.severity(),
                        "Rejecting HostRoutingRecord: {}", err
                    );
                    return Err(err.into());
                }
            }
        } else {
            let err = KineticStoreError::UnknownRecordType;
            tracing::warn!(
                error_code = "KIN-STORE-019",
                severity = ?err.severity(),
                "Rejecting Kademlia record: {}", err
            );
            return Err(err.into());
        }

        let sled_key = format!("kad_record:{}", hex::encode(r.key.as_ref()));
        let _ = self.storage.put(sled_key.as_bytes(), &r.value);
        self.inner.put(r)
    }

    fn remove(&mut self, k: &kad::RecordKey) {
        self.inner.remove(k)
    }

    fn records(&self) -> Self::RecordsIter<'_> {
        self.inner.records()
    }

    fn add_provider(&mut self, _record: kad::ProviderRecord) -> kad::store::Result<()> {
        // Case 183: Kinetic strictly uses PutRecord. ProviderRecords are disabled globally to prevent Provider Spam.
        Err(kad::store::Error::MaxProvidedKeys)
    }

    fn providers(&self, key: &kad::RecordKey) -> Vec<kad::ProviderRecord> {
        self.inner.providers(key)
    }

    fn provided(&self) -> Self::ProvidedIter<'_> {
        self.inner.provided()
    }

    fn remove_provider(&mut self, k: &kad::RecordKey, p: &PeerId) {
        self.inner.remove_provider(k, p)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::identity::Keypair;
    use tempfile::tempdir;

    #[test]
    fn test_store_rejects_garbage() {
        let dir = tempdir().unwrap();
        let sled_storage = Arc::new(SledStorage::new(dir.path()).unwrap());
        let keypair = Keypair::generate_ed25519();
        let peer_id = PeerId::from(keypair.public());

        let mut store = KineticRecordStore::new(peer_id, sled_storage, 0);

        let record = kad::Record::new(
            kad::RecordKey::new(&b"garbage".to_vec()),
            b"invalid json payload".to_vec(),
        );

        let res = store.put(record);
        assert!(res.is_err()); // Should reject
    }
}
