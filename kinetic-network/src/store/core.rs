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

    /// Tracks domain registration commitments by their hash and Drand round.
    pub commitments_by_hash: HashMap<[u8; 32], u64>,
    /// The points balance available to each public key.
    pub points_by_pubkey: HashMap<Vec<u8>, u64>,
    /// History of timestamps for accepted reveals used for rate limiting.
    pub accepted_reveals_timestamps: std::collections::VecDeque<web_time::Instant>,
    /// The current observed Drand pulse round.
    pub current_drand_round: u64,
}

impl KineticRecordStore {
    /// Creates a new `KineticRecordStore` instance and restores existing state from sled storage.
    pub fn new(local_peer_id: PeerId, storage: Arc<SledStorage>, initial_drand_round: u64) -> Self {
        let mut reveals_by_name = LruCache::new(NonZeroUsize::new(10_000).unwrap());
        let mut last_heartbeats_by_name = HashMap::new();


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

        let max_age_rounds = kinetic_core::types::RESQUARING_EPOCH_ROUNDS; // Finding 3: use shared constant
        let idle_timeout = (14 * 24 * 3600) / 30; // 14 days in 30s rounds

        let mut expired_names = Vec::new();

        for (name, reveal) in &self.reveals_by_name {
            // Genesis Infinity Lock has been removed by the Founder.
            // All domains, including Genesis names, are subject to thermodynamic pruning.

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

            if !kinetic_core::types::infrastructure::requires_heartbeat(name) {
                continue; // Category 2 names are permanently exempt from thermodynamic pruning
            }



            if hb_age > idle_timeout {
                expired_names.push(name.clone());
            }
        }

        for name in expired_names {
            tracing::info!("Pruning expired/idle name: {}", name);
            self.reveals_by_name.pop(&name);
            self.last_heartbeats_by_name.remove(&name);


            let _ = self
                .storage
                .delete(format!("{}{}", KRS_REVEAL_PREFIX, name).as_bytes());
            let _ = self
                .storage
                .delete(format!("{}{}", KRS_HB_PREFIX, name).as_bytes());


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

        } else if let Ok(heartbeat) =
            serde_json::from_slice::<kinetic_core::types::Heartbeat>(&r.value)
        {
            tracing::info!(
                "KineticRecordStore::put parsed Heartbeat for {}",
                heartbeat.name
            );
            self.handle_heartbeat(&heartbeat)?;
        } else if let Ok(auth_kid) =
            serde_json::from_slice::<kinetic_core::types::AuthorizedKid>(&r.value)
        {
            let active_reveal = self.reveals_by_name.get(&auth_kid.name);
            if let Err(e) = super::verification::verify_authorized_kid(&auth_kid, active_reveal) {
                return Err(e.into());
            }
        } else if let Ok(auth_manifest) =
            serde_json::from_slice::<kinetic_core::types::AuthorizedManifest>(&r.value)
        {
            let active_reveal = self.reveals_by_name.get(&auth_manifest.name);
            if let Err(e) = super::verification::verify_authorized_manifest(&auth_manifest, active_reveal) {
                return Err(e.into());
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
