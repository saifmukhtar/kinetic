use libp2p::{kad, PeerId};
use libp2p::kad::store::RecordStore;
use std::collections::HashMap;
use std::sync::Arc;


use kinetic_core::traits::StorageEngine;
use kinetic_storage::SledStorage;

pub const KRS_REVEAL_PREFIX: &str = "krs_reveal:";
pub const KRS_HB_PREFIX: &str = "krs_hb:";
pub const KRS_HIB_PREFIX: &str = "krs_hib:";

pub struct KineticRecordStore {
    inner: kad::store::MemoryStore,
    pub storage: Arc<SledStorage>,
    pub reveals_by_name: HashMap<String, kinetic_core::types::Reveal>,
    pub last_heartbeats_by_name: HashMap<String, u64>,
    pub hibernations_by_name: HashMap<String, (u64, u64)>, // (drand_round, iterations)
    pub commitments_by_hash: HashMap<[u8; 32], u64>,
    pub accepted_reveals_timestamps: std::collections::VecDeque<std::time::Instant>,
    pub current_drand_round: u64,
}

impl KineticRecordStore {
    pub fn new(local_peer_id: PeerId, storage: Arc<SledStorage>, initial_drand_round: u64) -> Self {
        let mut reveals_by_name = HashMap::new();
        let mut last_heartbeats_by_name = HashMap::new();
        let mut hibernations_by_name = HashMap::new();

        // Restore state from sled
        if let Ok(iter) = storage.scan_prefix(KRS_REVEAL_PREFIX.as_bytes()) {
            for (key_bytes, val_bytes) in iter {
                let key_str = String::from_utf8_lossy(&key_bytes).to_string();
                let name = key_str.trim_start_matches(KRS_REVEAL_PREFIX).to_string();
                if let Ok(reveal) = serde_json::from_slice::<kinetic_core::types::Reveal>(&val_bytes) {
                    tracing::info!("[KRS restore] Reveal for {}", name);
                    reveals_by_name.insert(name, reveal);
                }
            }
        }
        
        if let Ok(iter) = storage.scan_prefix(KRS_HB_PREFIX.as_bytes()) {
            for (key_bytes, val_bytes) in iter {
                let key_str = String::from_utf8_lossy(&key_bytes).to_string();
                let name = key_str.trim_start_matches(KRS_HB_PREFIX).to_string();
                if val_bytes.len() == 8 {
                    let round = u64::from_be_bytes(val_bytes[..8].try_into().unwrap_or([0u8;8]));
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
                    let round = u64::from_be_bytes(val_bytes[0..8].try_into().unwrap_or([0u8;8]));
                    let iters = u64::from_be_bytes(val_bytes[8..16].try_into().unwrap_or([0u8;8]));
                    tracing::info!("[KRS restore] Hibernation round {} (iters: {}) for {}", round, iters, name);
                    hibernations_by_name.insert(name, (round, iters));
                } else if val_bytes.len() == 8 {
                    let round = u64::from_be_bytes(val_bytes[..8].try_into().unwrap_or([0u8;8]));
                    hibernations_by_name.insert(name, (round, 500_000_000));
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
            commitments_by_hash: HashMap::new(),
            accepted_reveals_timestamps: std::collections::VecDeque::new(),
            current_drand_round: initial_drand_round,
        }
    }

    fn handle_reveal(&mut self, reveal: &kinetic_core::types::Reveal) -> Result<(), kad::store::Error> {
        if self.current_drand_round.saturating_sub(reveal.drand_pulse) > 1_000_000 {
            tracing::warn!("Rejecting Reveal for {}: VDF proof is too old (> 1 year)", reveal.name);
            return Err(kad::store::Error::ValueTooLarge);
        }

        if !self.verify_reveal_internal(reveal) {
            return Err(kad::store::Error::ValueTooLarge);
        }

        if let Some(existing_reveal) = self.reveals_by_name.get(&reveal.name) {
            if existing_reveal.pubkey != reveal.pubkey {
                let consensus_math = kinetic_core::consensus_math::ConsensusParams::default();
                let last_hb_round = self.last_heartbeats_by_name.get(&reveal.name).copied().unwrap_or(0);
                
                if let Some(&(hib_round, hib_iters)) = self.hibernations_by_name.get(&reveal.name) {
                    let hib_age = self.current_drand_round.saturating_sub(hib_round);
                    let exemption_rounds = consensus_math.hibernation_exemption_rounds(hib_iters);
                    if hib_age < exemption_rounds {
                        tracing::warn!(
                            "Rejecting Steal Reveal for {}: Name is hibernating (exemption lasts {} rounds, {} rounds elapsed)",
                            reveal.name, exemption_rounds, hib_age
                        );
                        return Err(kad::store::Error::ValueTooLarge);
                    }
                }

                let hb_age = self.current_drand_round.saturating_sub(last_hb_round);
                let base_diff = consensus_math.required_iterations(&reveal.name, reveal.drand_pulse, &reveal.pubkey);
                let steal_threshold = consensus_math.steal_difficulty(base_diff, hb_age);
                
                if reveal.iterations < steal_threshold {
                    tracing::warn!("Rejecting Steal Reveal for {}: Iterations {} below mathematical decay steal threshold ({}) for being idle {} rounds", reveal.name, reveal.iterations, steal_threshold, hb_age);
                    return Err(kad::store::Error::ValueTooLarge);
                }
                tracing::info!("Valid Steal Reveal for {}! Overwriting previous owner (idle for {} rounds).", reveal.name, hb_age);
            }
        }

        self.reveals_by_name.insert(reveal.name.clone(), reveal.clone());
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

        let current_round = self.current_drand_round;
        self.last_heartbeats_by_name.insert(reveal.name.clone(), current_round);
        let hb_key = format!("{}{}", KRS_HB_PREFIX, reveal.name);
        let _ = self.storage.put(hb_key.as_bytes(), &current_round.to_be_bytes());

        Ok(())
    }

    fn handle_hibernation(&mut self, hibernation: &kinetic_core::types::Hibernation) -> Result<(), kad::store::Error> {
        let existing_reveal = match self.reveals_by_name.get(&hibernation.name) {
            Some(r) => r,
            None => return Err(kad::store::Error::ValueTooLarge),
        };

        let signable = hibernation.signable_bytes();
        let pubkey = ed25519_dalek::VerifyingKey::try_from(existing_reveal.pubkey.as_slice())
            .map_err(|_| kad::store::Error::ValueTooLarge)?;
        let sig = ed25519_dalek::Signature::from_slice(&hibernation.signature)
            .map_err(|_| kad::store::Error::ValueTooLarge)?;
            
        use ed25519_dalek::Verifier;
        if pubkey.verify(&signable, &sig).is_err() {
            return Err(kad::store::Error::ValueTooLarge);
        }

        use sha2::{Sha256, Digest as _};
        use kinetic_core::traits::VdfEngine;
        use kinetic_vdf::ChiaVdfEngine;

        let challenge_bytes = hex::decode(&hibernation.drand_randomness)
            .unwrap_or_else(|_| vec![0u8; 32]);
        let mut hasher = Sha256::new();
        hasher.update(hibernation.name.as_bytes());
        hasher.update(&hibernation.salt);
        hasher.update(&challenge_bytes);
        hasher.update(&existing_reveal.pubkey);
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&hasher.finalize());
        let challenge = kinetic_core::types::Commitment { hash };

        let engine = ChiaVdfEngine::new();
        match engine.verify(&challenge, &hibernation.vdf_proof, hibernation.iterations) {
            Ok(true) => {
                let consensus_math = kinetic_core::consensus_math::ConsensusParams::default();
                let exemption_rounds = consensus_math.hibernation_exemption_rounds(hibernation.iterations);
                tracing::info!("Accepted valid Hibernation VDF for {}. Exempt from heartbeats for {} rounds.", hibernation.name, exemption_rounds);
                
                let current_round = self.current_drand_round;
                self.hibernations_by_name.insert(hibernation.name.clone(), (current_round, hibernation.iterations));
                let hib_key = format!("{}{}", KRS_HIB_PREFIX, hibernation.name);
                let mut val = Vec::new();
                val.extend_from_slice(&current_round.to_be_bytes());
                val.extend_from_slice(&hibernation.iterations.to_be_bytes());
                let _ = self.storage.put(hib_key.as_bytes(), &val);
                Ok(())
            }
            Ok(false) => {
                tracing::warn!("Hibernation for {} failed: VDF proof invalid for {} iterations", hibernation.name, hibernation.iterations);
                Err(kad::store::Error::ValueTooLarge)
            }
            Err(e) => {
                tracing::warn!("Hibernation for {} failed: VDF verification error: {}", hibernation.name, e);
                Err(kad::store::Error::ValueTooLarge)
            }
        }
    }

    fn handle_heartbeat(&mut self, heartbeat: &kinetic_core::types::Heartbeat) -> Result<(), kad::store::Error> {
        let existing_reveal = match self.reveals_by_name.get(&heartbeat.name) {
            Some(r) => r,
            None => return Err(kad::store::Error::ValueTooLarge),
        };

        let signable = heartbeat.signable_bytes();
        let pubkey = ed25519_dalek::VerifyingKey::try_from(existing_reveal.pubkey.as_slice())
            .map_err(|_| kad::store::Error::ValueTooLarge)?;
        let sig = ed25519_dalek::Signature::from_slice(&heartbeat.signature)
            .map_err(|_| kad::store::Error::ValueTooLarge)?;
            
        use ed25519_dalek::Verifier;
        if pubkey.verify(&signable, &sig).is_err() {
            tracing::warn!("Rejecting Heartbeat for {}: Invalid signature", heartbeat.name);
            return Err(kad::store::Error::ValueTooLarge);
        }

        tracing::info!("Accepted valid Heartbeat for {} at drand round {}", heartbeat.name, heartbeat.latest_drand_pulse);
        let hb_round = heartbeat.latest_drand_pulse;
        self.last_heartbeats_by_name.insert(heartbeat.name.clone(), hb_round);
        
        let hb_key = format!("{}{}", KRS_HB_PREFIX, heartbeat.name);
        let _ = self.storage.put(hb_key.as_bytes(), &hb_round.to_be_bytes());
        Ok(())
    }

    fn verify_reveal_internal(&self, reveal: &kinetic_core::types::Reveal) -> bool {
        use kinetic_core::types::Commitment;
        use ed25519_dalek::{Verifier, Signature, VerifyingKey};
        use sha2::{Sha256, Digest};
        use kinetic_core::traits::VdfEngine;
        use kinetic_vdf::ChiaVdfEngine;

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
        let challenge_bytes = hex::decode(&reveal.drand_randomness).unwrap_or_else(|_| vec![0u8; 32]);
        let mut hasher = Sha256::new();
        hasher.update(reveal.name.as_bytes());
        hasher.update(&reveal.salt);
        hasher.update(&challenge_bytes);
        hasher.update(&reveal.pubkey);
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&hasher.finalize());
        let challenge = Commitment { hash };

        if let Some(&commit_round) = self.commitments_by_hash.get(&hash) {
            tracing::info!("Commitment matched for Reveal of {} (committed around round {})", reveal.name, commit_round);
        } else {
            tracing::warn!("Rejecting Reveal for {}: No prior Commitment found in DHT!", reveal.name);
            return false;
        }

        let consensus_math = kinetic_core::consensus_math::ConsensusParams::default();
        let required_iterations = consensus_math.required_iterations(&reveal.name, reveal.drand_pulse, &reveal.pubkey);
        
        if reveal.iterations < required_iterations {
            tracing::warn!("Rejecting Kademlia Reveal: VDF iterations ({}) below required minimum ({})", reveal.iterations, required_iterations);
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
        self.inner.get(k)
    }

    fn put(&mut self, r: kad::Record) -> kad::store::Result<()> {
        tracing::info!("KineticRecordStore::put called for key: {:?}", r.key);
        
        if let Ok(commitment) = serde_json::from_slice::<kinetic_core::types::Commitment>(&r.value) {
            tracing::info!("KineticRecordStore::put parsed Commitment");
            self.commitments_by_hash.insert(commitment.hash, self.current_drand_round);
            return self.inner.put(r);
        }

        if let Ok(reveal) = serde_json::from_slice::<kinetic_core::types::Reveal>(&r.value) {
            tracing::info!("KineticRecordStore::put parsed Reveal for {}", reveal.name);
            self.handle_reveal(&reveal)?;
            return self.inner.put(r);
        }

        if let Ok(hibernation) = serde_json::from_slice::<kinetic_core::types::Hibernation>(&r.value) {
            tracing::info!("KineticRecordStore::put parsed Hibernation for {}", hibernation.name);
            self.handle_hibernation(&hibernation)?;
            return Ok(());
        }

        if let Ok(heartbeat) = serde_json::from_slice::<kinetic_core::types::Heartbeat>(&r.value) {
            tracing::info!("KineticRecordStore::put parsed Heartbeat for {}", heartbeat.name);
            self.handle_heartbeat(&heartbeat)?;
            return Ok(());
        }

        if let Ok(kid_doc) = serde_json::from_slice::<kinetic_kid::KidDocument>(&r.value) {
            if kid_doc.verify().is_ok() {
                tracing::info!("KineticRecordStore::put accepted valid KID Document for {}", kid_doc.kid.as_str());
                return self.inner.put(r);
            } else {
                tracing::warn!("Rejecting KID Document: Invalid signature");
                return Err(kad::store::Error::ValueTooLarge);
            }
        }

        if let Ok(manifest) = serde_json::from_slice::<kinetic_kid::CapabilityManifest>(&r.value) {
            tracing::info!("KineticRecordStore::put accepted Capability Manifest for {} (App layer must verify)", manifest.kid.as_str());
            return self.inner.put(r);
        }

        tracing::warn!("Rejecting Kademlia record: Neither Reveal, Hibernation, Heartbeat, KID, nor Manifest");
        Err(kad::store::Error::ValueTooLarge)
    }

    fn remove(&mut self, k: &kad::RecordKey) {
        self.inner.remove(k)
    }

    fn records(&self) -> Self::RecordsIter<'_> {
        self.inner.records()
    }

    fn add_provider(&mut self, record: kad::ProviderRecord) -> kad::store::Result<()> {
        self.inner.add_provider(record)
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
    use tempfile::tempdir;
    use libp2p::identity::Keypair;

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
