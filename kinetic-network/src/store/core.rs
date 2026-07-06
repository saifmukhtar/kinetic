use libp2p::{kad, PeerId};
use std::collections::HashMap;
use std::sync::Arc;

use kinetic_core::traits::StorageEngine;
use kinetic_storage::SledStorage;
use libp2p::kad::store::RecordStore;

use super::verification::verify_host_routing_record;
use crate::error::KineticStoreError;
use lru::LruCache;
use std::num::NonZeroUsize;

use crate::store::constants::*;
/// Custom Kademlia record store for Kinetic name records.
pub struct KineticRecordStore {
    inner: kad::store::MemoryStore,
    /// Persistent storage backend.
    pub storage: Arc<SledStorage>,
    /// Cache of verified domain reveals.
    pub reveals_by_name: LruCache<String, kinetic_core::types::Reveal>,
    /// The latest heartbeat pulse observed for each domain.
    pub last_heartbeats_by_name: HashMap<String, u64>,
    /// The hibernation start round and requested duration for each domain.
    pub hibernations_by_name: HashMap<String, (u64, u64)>, // (drand_round, iterations)
    /// Tracks domain registration commitments by their hash and Drand round.
    pub commitments_by_hash: HashMap<[u8; 32], u64>,
    /// The points balance available to each public key.
    pub points_by_pubkey: HashMap<Vec<u8>, u64>,
    /// History of timestamps for accepted reveals used for rate limiting.
    pub accepted_reveals_timestamps: std::collections::VecDeque<std::time::Instant>,
    /// The current observed Drand pulse round.
    pub current_drand_round: u64,
}

impl KineticRecordStore {
    /// Creates a new `KineticRecordStore` instance and restores existing state from sled storage.
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
                    let hash_hex =
                        String::from_utf8_lossy(&key_bytes[KRS_COMMIT_PREFIX.len()..]).to_string();
                    if let Ok(hash) = hex::decode(&hash_hex) {
                        if hash.len() == 32 && val_bytes.len() == 8 {
                            let mut hash_arr = [0u8; 32];
                            hash_arr.copy_from_slice(&hash);
                            let round =
                                u64::from_be_bytes(val_bytes[..8].try_into().unwrap_or([0u8; 8]));
                            commitments_by_hash.insert(hash_arr, round);
                        }
                    }
                }
            }
        }

        let mut points_by_pubkey = HashMap::new();
        if let Ok(iter) = storage.scan_prefix(KRS_POINTS_PREFIX.as_bytes()) {
            for (key_bytes, val_bytes) in iter {
                let key_str = String::from_utf8_lossy(&key_bytes).to_string();
                let pubkey_hex = key_str.trim_start_matches(KRS_POINTS_PREFIX);
                if let Ok(pubkey) = hex::decode(pubkey_hex) {
                    if val_bytes.len() == 8 {
                        let points =
                            u64::from_be_bytes(val_bytes[..8].try_into().unwrap_or([0u8; 8]));
                        points_by_pubkey.insert(pubkey, points);
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
            points_by_pubkey,
            accepted_reveals_timestamps: std::collections::VecDeque::new(),
            current_drand_round: initial_drand_round,
        }
    }
    /// Prunes expired records based on Drand pulse progression.
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
            if let Some(genesis_pk) = kinetic_core::consensus_math::ConsensusParams::GENESIS_PUBKEY
            {
                let normalized_name = kinetic_core::types::normalize_name(name);
                let label_without_tld = normalized_name
                    .strip_suffix(kinetic_core::types::DOT_TLD)
                    .unwrap_or(&normalized_name);
                if kinetic_core::consensus_math::ConsensusParams::GENESIS_ALLOWLIST
                    .contains(&label_without_tld)
                    && reveal.pubkey.as_slice() == genesis_pk
                {
                    tracing::debug!(
                        "Genesis Infinity Lock active for {}. Bypassing pruning.",
                        name
                    );
                    continue;
                }
            }
            // -----------------------------

            let age = current_round.saturating_sub(reveal.drand_pulse);
            if age > max_age_rounds {
                expired_names.push(name.clone());
                continue;
            }

            let last_hb = self
                .last_heartbeats_by_name
                .get(name)
                .copied()
                .unwrap_or(reveal.drand_pulse);
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
    pub(crate) fn verify_reveal_internal(&self, reveal: &kinetic_core::types::Reveal) -> bool {
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

        let dev_mode = kinetic_core::config::is_dev_mode();

        if let Some(&commit_round) = self.commitments_by_hash.get(&hash) {
            if !dev_mode && self.current_drand_round.saturating_sub(commit_round) < 10 {
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
        } else if !dev_mode {
            tracing::warn!(
                "Rejecting Reveal for {}: No prior Commitment found in DHT!",
                reveal.name
            );
            return false;
        } else {
            tracing::info!(
                "Dev mode: Bypassing commitment presence check for {}",
                reveal.name
            );
        }

        let consensus_math = kinetic_core::consensus_math::ConsensusParams::default();
        let base_required_iterations =
            consensus_math.required_iterations(&reveal.name, reveal.drand_pulse, &reveal.pubkey);

        let mut required_iterations = if let Some(prev) = &reveal.previous_proof {
            // Verify previous proof
            let mut prev_hasher = Sha256::new();
            prev_hasher.update(reveal.name.as_bytes());
            prev_hasher.update(prev.salt);
            prev_hasher
                .update(hex::decode(&prev.drand_randomness).unwrap_or_else(|_| vec![0u8; 32]));
            prev_hasher.update(&reveal.pubkey);
            let mut prev_hash = [0u8; 32];
            prev_hash.copy_from_slice(&prev_hasher.finalize());
            let prev_challenge = Commitment { hash: prev_hash };

            let prev_valid = matches!(
                engine.verify(&prev_challenge, &prev.vdf_proof, prev.iterations),
                Ok(true)
            );

            let prev_req =
                consensus_math.required_iterations(&reveal.name, prev.drand_pulse, &reveal.pubkey);
            let is_not_too_old = self.current_drand_round.saturating_sub(prev.drand_pulse)
                <= kinetic_core::types::RESQUARING_EPOCH_ROUNDS * 2;

            if prev_valid && prev.iterations >= prev_req && is_not_too_old {
                tracing::info!(
                    "Valid PreviousProof attached for {}. Granting 80% VDF iteration discount.",
                    reveal.name
                );
                std::cmp::max(1, base_required_iterations / 5)
            } else {
                tracing::warn!(
                    "Invalid PreviousProof attached for {}. Falling back to full difficulty.",
                    reveal.name
                );
                base_required_iterations
            }
        } else {
            base_required_iterations
        };

        if let Some(spent) = reveal.points_spent {
            if spent > 0 {
                let balance = self
                    .points_by_pubkey
                    .get(&reveal.pubkey)
                    .copied()
                    .unwrap_or(0);
                if balance < spent {
                    tracing::warn!(
                        "Rejecting Reveal for {}: Insufficient points (spent {}, balance {})",
                        reveal.name,
                        spent,
                        balance
                    );
                    return false;
                }
                required_iterations = required_iterations.saturating_sub(spent);
                tracing::info!(
                    "Reveal for {} spent {} points. Reduced required iterations to {}.",
                    reveal.name,
                    spent,
                    required_iterations
                );
            }
        }

        if dev_mode {
            tracing::info!(
                "Dev mode: Bypassing VDF proof verification for {}",
                reveal.name
            );
            return true;
        }

        if reveal.iterations < required_iterations {
            tracing::warn!(
                "Rejecting Reveal: Insufficient VDF iterations. Provided {}, Required {}",
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
            let _ = self
                .storage
                .put(key.as_bytes(), &self.current_drand_round.to_be_bytes());
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
