use libp2p::{kad, PeerId};
use std::collections::HashMap;
use std::sync::Arc;

use kinetic_core::traits::StorageEngine;
use kinetic_storage::SledStorage;
use libp2p::kad::store::RecordStore;


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

    /// History of timestamps for accepted reveals used for rate limiting.
    pub accepted_reveals_timestamps: std::collections::VecDeque<web_time::Instant>,
    /// The current observed Drand pulse round.
    pub current_drand_round: u64,
    /// Configuration for rate limiting reveals
    pub max_reveals_per_hour: usize,
}

impl KineticRecordStore {
    /// Creates a new `KineticRecordStore` instance and restores existing state from sled storage.
    pub fn new(local_peer_id: PeerId, storage: Arc<SledStorage>, initial_drand_round: u64, lru_cache_size: NonZeroUsize, max_reveals_per_hour: usize) -> Self {
        let mut reveals_by_name = LruCache::new(lru_cache_size);
        let mut last_heartbeats_by_name = HashMap::new();

        // Restore state from sled
        if let Ok(iter) = storage.scan_prefix(KRS_REVEAL_PREFIX) {
            for (key_bytes, val_bytes) in iter {
                let prefix_len = KRS_REVEAL_PREFIX.len();
                if key_bytes.len() <= prefix_len { continue; }
                let name = String::from_utf8_lossy(&key_bytes[prefix_len..]).into_owned();
                if let Ok(reveal) =
                    serde_json::from_slice::<kinetic_core::types::Reveal>(&val_bytes)
                {
                    tracing::info!("[KRS restore] Reveal for {}", name);
                    reveals_by_name.put(name, reveal);
                }
            }
        }

        if let Ok(iter) = storage.scan_prefix(KRS_HB_PREFIX) {
            for (key_bytes, val_bytes) in iter {
                let prefix_len = KRS_HB_PREFIX.len();
                if key_bytes.len() <= prefix_len { continue; }
                let name = String::from_utf8_lossy(&key_bytes[prefix_len..]).into_owned();
                if val_bytes.len() == 8 {
                    let round = u64::from_be_bytes(val_bytes[..8].try_into().unwrap_or([0u8; 8]));
                    tracing::info!("[KRS restore] Heartbeat round {} for {}", round, name);
                    last_heartbeats_by_name.insert(name, round);
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
            accepted_reveals_timestamps: std::collections::VecDeque::new(),
            current_drand_round: initial_drand_round,
            max_reveals_per_hour,
        }
    }
    /// Prunes expired records based on Drand pulse progression.
    pub fn prune(&mut self) {
        let current_round = self.current_drand_round;
        let mut keys_to_delete = Vec::new();

        // 1. Scan and Prune Commitments from Sled
        if let Ok(iter) = self.storage.scan_prefix(KRS_COMMIT_PREFIX) {
            for (key_bytes, val_bytes) in iter {
                if val_bytes.len() == 8 {
                    let round = u64::from_be_bytes(val_bytes[..8].try_into().unwrap_or([0u8; 8]));
                    if current_round.saturating_sub(round) >= 100 {
                        keys_to_delete.push(key_bytes.to_vec());
                    }
                }
            }
        }

        let max_age_rounds = kinetic_core::types::RESQUARING_EPOCH_ROUNDS;
        let idle_timeout = (14 * 24 * 3600) / 30;

        let mut expired_names = Vec::new();

        for (name, reveal) in &self.reveals_by_name {
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
                continue;
            }

            if hb_age > idle_timeout {
                expired_names.push(name.clone());
            }
        }

        for name in expired_names {
            tracing::info!("Pruning expired/idle name: {}", name);
            self.reveals_by_name.pop(&name);
            self.last_heartbeats_by_name.remove(&name);

            keys_to_delete.push([KRS_REVEAL_PREFIX, name.as_bytes()].concat());
            keys_to_delete.push([KRS_HB_PREFIX, name.as_bytes()].concat());

            let keys = kinetic_core::types::derive_storage_keys(&name);
            for key_bytes in keys {
                let k = kad::RecordKey::new(&key_bytes);
                let mut sled_key = Vec::with_capacity(11 + k.as_ref().len());
                sled_key.extend_from_slice(b"kad_record:");
                sled_key.extend_from_slice(k.as_ref());
                keys_to_delete.push(sled_key);
            }

            let hb_keys = kinetic_core::types::derive_heartbeat_keys(&name);
            for key_bytes in hb_keys {
                let k = kad::RecordKey::new(&key_bytes);
                let mut sled_key = Vec::with_capacity(11 + k.as_ref().len());
                sled_key.extend_from_slice(b"kad_record:");
                sled_key.extend_from_slice(k.as_ref());
                keys_to_delete.push(sled_key);
            }
        }

        if !keys_to_delete.is_empty() {
            let storage = self.storage.clone();
            crate::event_loop::utils::spawn(async move {
                let _ = tokio::task::spawn_blocking(move || {
                    for key in keys_to_delete {
                        let _ = storage.delete(&key);
                    }
                })
                .await;
            });
        }
    }
}


impl KineticRecordStore {
    /// Attempts to put a record, returning a typed KineticStoreError on failure.
    pub fn put_record(&mut self, r: kad::Record) -> Result<(), KineticStoreError> {
        tracing::info!("KineticRecordStore::put called for key: {:?}", r.key);

        if r.value.len() > 16 * 1024 {
            let err = KineticStoreError::PayloadTooLarge;
            tracing::warn!(
                error_code = "KIN-STORE-016",
                size = r.value.len(),
                severity = ?err.severity(),
                "Rejecting Kademlia record: {}", err
            );
            return Err(err);
        }

        if let Ok(parsed) = serde_json::from_slice::<serde_json::Value>(&r.value) {
            if parsed.get("hash").is_some() && parsed.get("vdf_proof").is_none() {
                if let Ok(commitment) = serde_json::from_value::<kinetic_core::types::Commitment>(parsed) {
                    tracing::info!("KineticRecordStore::put parsed Commitment");
                    let mut key = Vec::with_capacity(KRS_COMMIT_PREFIX.len() + 32);
                    key.extend_from_slice(KRS_COMMIT_PREFIX);
                    key.extend_from_slice(&commitment.hash);
                    let _ = self
                        .storage
                        .put(&key, &self.current_drand_round.to_be_bytes());
                    return self.inner.put(r).map_err(|_| KineticStoreError::PayloadTooLarge);
                }
            } else if parsed.get("vdf_proof").is_some() {
                if let Ok(reveal) = serde_json::from_value::<kinetic_core::types::Reveal>(parsed) {
                    tracing::info!("KineticRecordStore::put parsed Reveal for {}", reveal.name);
                    self.handle_reveal(&reveal)?;
                }
            } else if parsed.get("node_id").is_some() {
                if let Ok(heartbeat) = serde_json::from_value::<kinetic_core::types::Heartbeat>(parsed) {
                    tracing::info!("KineticRecordStore::put parsed Heartbeat for {}", heartbeat.name);
                    self.handle_heartbeat(&heartbeat)?;
                }
            } else if parsed.get("delegation_signature").is_some() {
                if let Ok(auth_kid) = serde_json::from_value::<kinetic_core::types::AuthorizedKid>(parsed) {
                    let active_reveal = self.reveals_by_name.get(&auth_kid.name);
                    if let Err(e) = super::verification::verify_authorized_kid(&auth_kid, active_reveal) {
                        return Err(e);
                    }
                }
            } else if parsed.get("manifest").is_some() {
                if let Ok(auth_manifest) = serde_json::from_value::<kinetic_core::types::AuthorizedManifest>(parsed) {
                    let active_reveal = self.reveals_by_name.get(&auth_manifest.name);
                    if let Err(e) = super::verification::verify_authorized_manifest(&auth_manifest, active_reveal) {
                        return Err(e);
                    }
                }
            } else if parsed.get("host_id").is_some() {
                if let Ok(host_route) = serde_json::from_value::<kinetic_core::types::HostRoutingRecord>(parsed) {
                    match crate::store::verification::verify_host_routing_record(&host_route) {
                        Ok(()) => {
                            tracing::info!("KineticRecordStore::put accepted verified HostRoutingRecord for {}", host_route.host_id);
                        }
                        Err(err) => {
                            tracing::warn!(error_code = "KIN-STORE-021", host_id = %host_route.host_id, severity = ?err.severity(), "Rejecting HostRoutingRecord: {}", err);
                            return Err(err);
                        }
                    }
                }
            } else {
                let err = KineticStoreError::UnknownRecordType;
                tracing::warn!(
                    error_code = "KIN-STORE-019",
                    severity = ?err.severity(),
                    "Rejecting Kademlia record: {}", err
                );
                return Err(err);
            }
        } else {
            let err = KineticStoreError::UnknownRecordType;
            tracing::warn!(
                error_code = "KIN-STORE-019",
                severity = ?err.severity(),
                "Rejecting Kademlia record: {}", err
            );
            return Err(err);
        }

        let mut sled_key = Vec::with_capacity(11 + r.key.as_ref().len());
        sled_key.extend_from_slice(b"kad_record:");
        sled_key.extend_from_slice(r.key.as_ref());
        let _ = self.storage.put(&sled_key, &r.value);
        self.inner.put(r).map_err(|_| KineticStoreError::PayloadTooLarge)
    }
}

impl kad::store::RecordStore for KineticRecordStore {
    type RecordsIter<'a> = <kad::store::MemoryStore as kad::store::RecordStore>::RecordsIter<'a>;
    type ProvidedIter<'a> = <kad::store::MemoryStore as kad::store::RecordStore>::ProvidedIter<'a>;

    fn get(&self, k: &kad::RecordKey) -> Option<std::borrow::Cow<'_, kad::Record>> {
        if let Some(record) = self.inner.get(k) {
            return Some(record);
        }

        let mut sled_key = Vec::with_capacity(11 + k.as_ref().len());
        sled_key.extend_from_slice(b"kad_record:");
        sled_key.extend_from_slice(k.as_ref());

        if let Ok(Some(bytes)) = self.storage.get(&sled_key) {
            let record = kad::Record::new(k.clone(), bytes.to_vec());
            return Some(std::borrow::Cow::Owned(record));
        }

        None
    }

    fn put(&mut self, r: kad::Record) -> kad::store::Result<()> {
        self.put_record(r).map_err(|e| e.into())
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

        let mut store = KineticRecordStore::new(peer_id, sled_storage, 0, NonZeroUsize::new(100).unwrap(), 100);

        let record = kad::Record::new(
            kad::RecordKey::new(&b"garbage".to_vec()),
            b"invalid json payload".to_vec(),
        );

        let res = store.put(record);
        assert!(res.is_err()); // Should reject
    }
}
