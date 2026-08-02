//! Custom Kademlia `RecordStore` implementation managing persistent Sled storage, LRU caching, and validation dispatching.
//!
//! This module defines the [`KineticRecordStore`], which implements libp2p's
//! [`RecordStore`](libp2p::kad::store::RecordStore) trait. It intercepts DHT
//! `put` requests to strictly enforce Kinetic protocol rules, such as VDF proof
//! validation, Ed25519 signature checks, and heartbeat timestamp progression,
//! before persisting records to the underlying `sled` database.
use libp2p::{kad, PeerId};
use std::collections::HashMap;
use std::sync::Arc;

use kinetic_core::traits::StorageEngine;
use libp2p::kad::store::RecordStore;

use crate::error::KineticStoreError;
use lru::LruCache;
use std::num::NonZeroUsize;

use crate::store::constants::*;

/// Custom Kademlia record store for Kinetic name records.
///
/// Implements `libp2p::kad::store::RecordStore` to provide domain validation,
/// commit-reveal timelocks, heartbeat liveness tracking, and sled persistence.
pub struct KineticRecordStore {
    inner: kad::store::MemoryStore,
    /// Persistent storage backend.
    pub storage: Arc<dyn StorageEngine>,
    /// VDF Engine used for proof validation.
    pub vdf_engine: Arc<dyn kinetic_core::traits::VdfEngine>,
    /// Cache of verified domain records.
    pub reveals_by_name: LruCache<String, kinetic_core::types::DomainRecord>,
    /// The latest heartbeat pulse observed for each domain.
    pub last_heartbeats_by_name: HashMap<String, u64>,

    /// History of timestamps for accepted reveals used for rate limiting per name.
    pub accepted_reveals_timestamps:
        LruCache<String, std::collections::VecDeque<web_time::Instant>>,
    /// The current observed Drand pulse round.
    pub current_drand_round: u64,
    /// Configuration for rate limiting reveals
    pub max_reveals_per_hour: usize,
}

impl KineticRecordStore {
    /// Creates a new `KineticRecordStore` instance and restores existing state from sled storage.
    ///
    /// This initialization phase scans the persistent storage for existing reveals and heartbeats,
    /// re-verifying their validity (including VDF proofs and Ed25519 signatures) before
    /// repopulating the memory caches. Invalid or stale records are discarded.
    ///
    /// # Arguments
    ///
    /// * `local_peer_id` - The libp2p [`PeerId`] of the local node.
    /// * `storage` - A thread-safe reference to the underlying sled database wrapper.
    /// * `initial_drand_round` - The starting drand pulse round to initialize the store.
    /// * `lru_cache_size` - The maximum number of reveals to cache in memory.
    /// * `max_reveals_per_hour` - Rate limit configuration for incoming reveals per domain name.
    /// * `vdf_engine` - The backend engine used to verify VDF proofs.
    /// * `gov_state` - The global governance state for emergency pause checks.
    ///
    /// # Panics
    ///
    /// Panics if the internal `storage` fails to parse basic numbers or during unwrap in fallback scenarios.
    pub fn new(
        local_peer_id: PeerId,
        storage: Arc<dyn StorageEngine>,
        initial_drand_round: u64,
        lru_cache_size: NonZeroUsize,
        max_reveals_per_hour: usize,
        vdf_engine: Arc<dyn kinetic_core::traits::VdfEngine>,
    ) -> Self {
        let mut reveals_by_name = LruCache::new(lru_cache_size);
        let mut last_heartbeats_by_name = HashMap::new();

        // Restore state from sled
        // Added limit to prevent memory exhaustion
        if let Ok(iter) = storage.scan_prefix(KRS_REVEAL_PREFIX, Some(100_000)) {
            for (key_bytes, val_bytes) in iter {
                let prefix_len = KRS_REVEAL_PREFIX.len();
                if key_bytes.len() <= prefix_len {
                    continue;
                }
                let name = String::from_utf8_lossy(&key_bytes[prefix_len..]).into_owned();
                if let Ok(record) =
                    serde_json::from_slice::<kinetic_core::types::DomainRecord>(&val_bytes)
                {
                    let mut is_valid = false;
                    match &record {
                        kinetic_core::types::DomainRecord::Standard(reveal) => {
                            if let Ok(req) = super::verification::compute_required_iterations(
                                reveal,
                                initial_drand_round,
                                vdf_engine.as_ref(),
                            ) {
                                if reveal.iterations >= req {
                                    let dev_mode = kinetic_core::config::is_dev_mode();
                                    if dev_mode
                                        || reveal
                                            .verify_signature(kinetic_core::constants::NETWORK_ID)
                                            .is_ok()
                                    {
                                        use kinetic_core::types::Commitment;
                                        use sha2::{Digest, Sha256};
                                        let drand_sig_bytes = hex::decode(&reveal.drand_signature)
                                            .unwrap_or_else(|_| vec![0u8; 32]);
                                        let mut drand_hasher = Sha256::new();
                                        drand_hasher.update(&drand_sig_bytes);
                                        let mut drand_rand = [0u8; 32];
                                        drand_rand.copy_from_slice(&drand_hasher.finalize());

                                        let mut hasher = Sha256::new();
                                        hasher.update(reveal.name.as_bytes());
                                        hasher.update(reveal.salt);
                                        hasher.update(&drand_rand);
                                        hasher.update(&reveal.pubkey);
                                        let mut hash = [0u8; 32];
                                        hash.copy_from_slice(&hasher.finalize());
                                        let challenge = Commitment { hash };

                                        #[cfg(not(target_arch = "wasm32"))]
                                        let is_valid_vdf = tokio::task::block_in_place(|| {
                                            vdf_engine.verify(
                                                &challenge,
                                                &reveal.vdf_proof,
                                                reveal.iterations,
                                            )
                                        });
                                        #[cfg(target_arch = "wasm32")]
                                        let is_valid_vdf = vdf_engine.verify(
                                            &challenge,
                                            &reveal.vdf_proof,
                                            reveal.iterations,
                                        );

                                        if matches!(is_valid_vdf, Ok(true)) {
                                            is_valid = true;
                                        }
                                    }
                                }
                            }
                        }
                        kinetic_core::types::DomainRecord::Premium { .. } => {
                            // Premium domains injected by governance are implicitly valid.
                            is_valid = true;
                        }
                    }

                    if is_valid {
                        tracing::info!("[KRS restore] DomainRecord for {}", name);
                        reveals_by_name.put(name, record);
                    } else {
                        tracing::warn!(
                            "[KRS restore] Discarding invalid locally stored DomainRecord for {}",
                            name
                        );
                    }
                }
            }
        }

        if let Ok(iter) = storage.scan_prefix(KRS_HB_PREFIX, None) {
            for (key_bytes, val_bytes) in iter {
                let prefix_len = KRS_HB_PREFIX.len();
                if key_bytes.len() <= prefix_len {
                    continue;
                }
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
                let keys = kinetic_core::types::derive_storage_keys(
                    name,
                    kinetic_core::constants::NETWORK_ID,
                );
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
            vdf_engine,
            reveals_by_name,
            last_heartbeats_by_name,
            accepted_reveals_timestamps: LruCache::new(lru_cache_size),
            current_drand_round: initial_drand_round,
            max_reveals_per_hour,
        }
    }
    /// Prunes expired records based on Drand pulse progression.
    ///
    /// This removes `Commitment` records that are older than 100 rounds,
    /// `Reveal` records older than the resquaring epoch, and idle heartbeats
    /// older than 7 days (where applicable for infrastructure).
    pub fn prune(&mut self) {
        let current_round = self.current_drand_round;
        let mut keys_to_delete = Vec::new();

        // 1. Scan and Prune Commitments from Sled
        if let Ok(iter) = self.storage.scan_prefix(KRS_COMMIT_PREFIX, None) {
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
        let idle_timeout = (7 * 24 * 3600) / 3; // 7 days of 3-second Drand rounds

        let mut expired_names = Vec::new();

        for (name, record) in &self.reveals_by_name {
            match record {
                kinetic_core::types::DomainRecord::Standard(reveal) => {
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
                kinetic_core::types::DomainRecord::Premium { .. } => {
                    // Premium names do not expire via drand resquaring, and don't require heartbeats.
                    continue;
                }
            }
        }

        for name in expired_names {
            tracing::info!("Pruning expired/idle name: {}", name);
            self.reveals_by_name.pop(&name);
            self.last_heartbeats_by_name.remove(&name);

            keys_to_delete.push([KRS_REVEAL_PREFIX, name.as_bytes()].concat());
            keys_to_delete.push([KRS_HB_PREFIX, name.as_bytes()].concat());

            let keys = kinetic_core::types::derive_storage_keys(
                &name,
                kinetic_core::constants::NETWORK_ID,
            );
            for key_bytes in keys {
                let k = kad::RecordKey::new(&key_bytes);
                let mut sled_key = Vec::with_capacity(11 + k.as_ref().len());
                sled_key.extend_from_slice(b"kad_record:");
                sled_key.extend_from_slice(k.as_ref());
                keys_to_delete.push(sled_key);
            }

            let hb_keys = kinetic_core::types::derive_heartbeat_keys(
                &name,
                kinetic_core::constants::NETWORK_ID,
            );
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
                let _ = crate::event_loop::utils::spawn_blocking(move || {
                    for key in keys_to_delete {
                        let _ = storage.delete(&key);
                    }
                })
                .await;
            });
        }
    }

    pub(crate) fn get_record_with_fallback(
        &mut self,
        name: &str,
    ) -> Option<kinetic_core::types::DomainRecord> {
        if let Some(r) = self.reveals_by_name.get(name) {
            return Some(r.clone());
        }
        let key = [crate::store::constants::KRS_REVEAL_PREFIX, name.as_bytes()].concat();
        if let Ok(Some(bytes)) = self.storage.get(&key) {
            if let Ok(record) = serde_json::from_slice::<kinetic_core::types::DomainRecord>(&bytes)
            {
                self.reveals_by_name.put(name.to_string(), record.clone());
                return Some(record);
            }
        }
        None
    }
}

impl KineticRecordStore {
    /// Attempts to put a record, returning a typed [`KineticStoreError`] on failure.
    ///
    /// This method enforces all Kinetic validation rules dynamically based on the payload type
    /// (e.g., `Commitment`, `Reveal`, `Heartbeat`, `AuthorizedKid`, `AuthorizedManifest`, `HostRoutingRecord`).
    ///
    /// # Arguments
    ///
    /// * `r` - The Kademlia record attempting to be stored.
    ///
    /// # Errors
    ///
    /// Returns a [`KineticStoreError`] if the record payload is malformed, cryptographic proofs fail,
    /// the heartbeat is stale, or the payload size exceeds the 80 KB limit (`KIN-NET-001`).
    pub fn put_record(&mut self, r: kad::Record) -> Result<(), KineticStoreError> {
        self.put_record_internal(r, false)
    }

    /// Attempts to put a record directly, bypassing VDF verification (for offloaded validation).
    ///
    /// This is used internally when an offloaded VDF verification task succeeds, allowing
    /// the record to be stored without duplicating the expensive validation.
    ///
    /// # Arguments
    ///
    /// * `r` - The pre-verified Kademlia record to be stored.
    ///
    /// # Errors
    ///
    /// Returns a [`KineticStoreError`] if the payload size exceeds the maximum 80 KB limit (`KIN-NET-001`).
    pub fn put_verified_record(&mut self, r: kad::Record) -> Result<(), KineticStoreError> {
        self.put_record_internal(r, true)
    }

    fn put_record_internal(
        &mut self,
        r: kad::Record,
        skip_reveal_verify: bool,
    ) -> Result<(), KineticStoreError> {
        tracing::trace!("KineticRecordStore::put called for key: {:?}", r.key);

        // The core schema limit (MAX_PAYLOAD_SIZE) is 64 KB (65,536 bytes).
        // This store limit is deliberately set higher (80 KB) to safely accommodate
        // the 64 KB payload plus any cryptographic proofs (VDFs, signatures) and
        // structural serialization overhead without rejecting valid payloads.
        if r.value.len() > kinetic_core::constants::LIMITS_STORAGE_MAX_VALUE_BYTES {
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
                match serde_json::from_value::<kinetic_core::types::Commitment>(parsed) {
                    Ok(commitment) => {
                        tracing::debug!("KineticRecordStore::put parsed Commitment");
                        let mut key = Vec::with_capacity(KRS_COMMIT_PREFIX.len() + 32);
                        key.extend_from_slice(KRS_COMMIT_PREFIX);
                        key.extend_from_slice(&commitment.hash);
                        let _ = self
                            .storage
                            .put(&key, &self.current_drand_round.to_be_bytes());
                        return self
                            .inner
                            .put(r)
                            .map_err(|_| KineticStoreError::PayloadTooLarge);
                    }
                    Err(_) => {
                        let err = KineticStoreError::UnknownRecordType;
                        return Err(err);
                    }
                }
            } else if parsed.get("vdf_proof").is_some() || parsed.get("granted_at").is_some() {
                match serde_json::from_value::<kinetic_core::types::DomainRecord>(parsed) {
                    Ok(record) => {
                        tracing::debug!(
                            "KineticRecordStore::put parsed DomainRecord for {}",
                            record.name()
                        );
                        self.handle_record(&record, skip_reveal_verify)?;
                    }
                    Err(_) => {
                        let err = KineticStoreError::UnknownRecordType;
                        return Err(err);
                    }
                }
            } else if parsed.get("latest_drand_pulse").is_some() {
                match serde_json::from_value::<kinetic_core::types::Heartbeat>(parsed) {
                    Ok(heartbeat) => {
                        tracing::trace!(
                            "KineticRecordStore::put parsed Heartbeat for {}",
                            heartbeat.name
                        );
                        self.handle_heartbeat(&heartbeat)?;
                    }
                    Err(_) => {
                        let err = KineticStoreError::UnknownRecordType;
                        return Err(err);
                    }
                }
            } else if parsed.get("delegation_signature").is_some() {
                match serde_json::from_value::<kinetic_core::types::AuthorizedKid>(parsed) {
                    Ok(auth_kid) => {
                        let active_record = self.get_record_with_fallback(&auth_kid.name);
                        let existing_record = self.inner.get(&r.key);
                        super::verification::verify_authorized_kid(
                            &auth_kid,
                            active_record.as_ref(),
                            existing_record.as_ref(),
                        )?;
                    }
                    Err(_) => {
                        let err = KineticStoreError::UnknownRecordType;
                        return Err(err);
                    }
                }
            } else if parsed.get("manifest").is_some() {
                match serde_json::from_value::<kinetic_core::types::AuthorizedManifest>(parsed) {
                    Ok(auth_manifest) => {
                        let active_record = self.get_record_with_fallback(&auth_manifest.name);
                        let existing_record = self.inner.get(&r.key);
                        super::verification::verify_authorized_manifest(
                            &auth_manifest,
                            active_record.as_ref(),
                            existing_record.as_ref(),
                        )?;
                    }
                    Err(_) => {
                        let err = KineticStoreError::UnknownRecordType;
                        return Err(err);
                    }
                }
            } else if parsed.get("host_id").is_some() {
                match serde_json::from_value::<kinetic_core::types::HostRoutingRecord>(parsed) {
                    Ok(host_route) => {
                        match crate::store::verification::verify_host_routing_record(&host_route, self.current_drand_round) {
                            Ok(()) => {
                                tracing::info!("KineticRecordStore::put accepted verified HostRoutingRecord for {}", host_route.host_id);
                            }
                            Err(err) => {
                                tracing::warn!(error_code = "KIN-STORE-021", host_id = %host_route.host_id, severity = ?err.severity(), "Rejecting HostRoutingRecord: {}", err);
                                return Err(err);
                            }
                        }
                    }
                    Err(_) => {
                        let err = KineticStoreError::UnknownRecordType;
                        return Err(err);
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
        self.inner
            .put(r)
            .map_err(|_| KineticStoreError::PayloadTooLarge)
    }
}

impl kad::store::RecordStore for KineticRecordStore {
    type RecordsIter<'a> = <kad::store::MemoryStore as kad::store::RecordStore>::RecordsIter<'a>;
    type ProvidedIter<'a> = <kad::store::MemoryStore as kad::store::RecordStore>::ProvidedIter<'a>;

    fn get(&self, k: &kad::RecordKey) -> Option<std::borrow::Cow<'_, kad::Record>> {
        self.inner.get(k)
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
    use kinetic_storage::SledStorage;
    use libp2p::identity::Keypair;
    use tempfile::tempdir;

    #[test]
    fn test_store_rejects_garbage() {
        let dir = tempdir().unwrap();
        let sled_storage = Arc::new(SledStorage::new(dir.path()).unwrap());
        let keypair = Keypair::generate_ed25519();
        let peer_id = PeerId::from(keypair.public());

        let vdf_engine: std::sync::Arc<dyn kinetic_core::traits::VdfEngine> =
            std::sync::Arc::new(kinetic_vdf::ChiaVdfEngine::new());
        let mut store = KineticRecordStore::new(
            peer_id,
            sled_storage,
            0,
            NonZeroUsize::new(100).unwrap(),
            100,
            vdf_engine,
        );

        let record = kad::Record::new(
            kad::RecordKey::new(&b"garbage".to_vec()),
            b"invalid json payload".to_vec(),
        );

        let res = store.put(record);
        assert!(res.is_err()); // Should reject
    }
}
