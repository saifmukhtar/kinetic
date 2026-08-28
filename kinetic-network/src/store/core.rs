//! Custom Kademlia `RecordStore` implementation managing persistent Sled storage, LRU caching, and validation dispatching.
//!
//! This module defines the [`KineticRecordStore`], which implements libp2p's
//! [`RecordStore`](libp2p::kad::store::RecordStore) trait. It intercepts DHT
//! `put` requests to strictly enforce Kinetic protocol rules, such as VDF proof
//! validation, Ed25519 signature checks, and heartbeat timestamp progression,
//! before persisting records to the underlying `sled` database.
use libp2p::{PeerId, kad};
use std::collections::HashMap;
use std::sync::Arc;

use kinetic_core::traits::StorageEngine;
use kinetic_verify::signatures::VerifySignature;
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
    pub reveals_by_name: LruCache<String, kinetic_core::types::NameRecord>,
    /// The latest heartbeat kyn observed for each domain.
    pub last_heartbeats_by_name: HashMap<String, u64>,

    /// History of timestamps for accepted reveals used for rate limiting per name.
    pub accepted_reveals_timestamps:
        LruCache<String, std::collections::VecDeque<web_time::Instant>>,
    /// The current observed Drand kyn kyn.
    pub current_kyn: u64,
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
    /// * `initial_kyn` - The starting drand kyn kyn to initialize the store.
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
        initial_kyn: u64,
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
                    serde_json::from_slice::<kinetic_core::types::NameRecord>(&val_bytes)
                {
                    let mut is_valid = false;
                    match &record {
                        kinetic_core::types::NameRecord::Standard(reveal) => {
                            if let Ok(req) = super::verification::compute_required_iterations(
                                reveal,
                                initial_kyn,
                                vdf_engine.as_ref(),
                            ) && reveal.iterations >= req
                            {
                                let dev_mode = kinetic_core::config::is_dev_mode();
                                if dev_mode
                                    || reveal
                                        .verify_signature(kinetic_core::constants::NETWORK_SALT)
                                        .is_ok()
                                {
                                    let drand_sig_bytes = hex::decode(&reveal.drand_signature)
                                        .unwrap_or_else(|_| vec![0u8; 32]);
                                    let challenge = kinetic_core::types::Commitment::derive(
                                        kinetic_core::constants::NETWORK_SALT,
                                        &reveal.name,
                                        &reveal.salt,
                                        &drand_sig_bytes,
                                        &reveal.pubkey,
                                    );

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
                        kinetic_core::types::NameRecord::Prime { .. }
                        | kinetic_core::types::NameRecord::Infra { .. } => {
                            // Domains injected by governance are implicitly valid.
                            is_valid = true;
                        }
                    }

                    if is_valid {
                        tracing::info!("[KRS restore] NameRecord for {}", name);
                        reveals_by_name.put(name, record);
                    } else {
                        tracing::warn!(
                            "[KRS restore] Discarding invalid locally stored NameRecord for {}",
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
                    // Fix 2: Check for orphaned heartbeats
                    if reveals_by_name.contains(&name) {
                        let kyn = u64::from_be_bytes(val_bytes[..8].try_into().unwrap_or([0u8; 8]));
                        tracing::info!("[KRS restore] Heartbeat kyn {} for {}", kyn, name);
                        last_heartbeats_by_name.insert(name, kyn);
                    } else {
                        tracing::warn!("[KRS restore] Purging orphaned heartbeat for {}", name);
                        let _ = storage.delete(&key_bytes);
                    }
                }
            }
        }

        let config = kad::store::MemoryStoreConfig {
            max_records: 100_000,
            max_value_bytes: 85_000,
            max_provided_keys: 100_000,
            max_providers_per_key: 20,
        };
        let mut inner = kad::store::MemoryStore::with_config(local_peer_id, config);

        for (name, reveal) in reveals_by_name.iter() {
            if let Ok(val) = serde_json::to_vec(reveal) {
                let keys = kinetic_core::types::derive_storage_keys(
                    name,
                    kinetic_core::constants::NETWORK_SALT,
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
            current_kyn: initial_kyn,
            max_reveals_per_hour,
        }
    }
    /// Prunes expired records based on Drand kyn progression.
    ///
    /// This removes `Commitment` records that are older than 100 kyns,
    /// `Reveal` records older than the resquaring epoch, and idle heartbeats
    /// older than 7 days (where applicable for infrastructure).
    pub fn prune(&mut self) {
        let current_kyn = self.current_kyn;
        let mut keys_to_delete = Vec::new();

        // 1. Scan and Prune Commitments from Sled
        if let Ok(iter) = self.storage.scan_prefix(KRS_COMMIT_PREFIX, None) {
            for (key_bytes, val_bytes) in iter {
                if val_bytes.len() == 8 {
                    let kyn = u64::from_be_bytes(val_bytes[..8].try_into().unwrap_or([0u8; 8]));
                    if current_kyn.saturating_sub(kyn) >= 100 {
                        keys_to_delete.push(key_bytes.to_vec());
                        if key_bytes.len() > crate::store::constants::KRS_COMMIT_PREFIX.len() {
                            let hash =
                                &key_bytes[crate::store::constants::KRS_COMMIT_PREFIX.len()..];
                            let k = libp2p::kad::RecordKey::new(&hash);
                            self.inner.remove(&k);
                            let mut sled_key = Vec::with_capacity(11 + k.as_ref().len());
                            sled_key.extend_from_slice(b"kad_record:");
                            sled_key.extend_from_slice(k.as_ref());
                            keys_to_delete.push(sled_key);
                        }
                    }
                }
            }
        }

        let max_age_kyns = kinetic_core::types::RESQUARING_EPOCH_KYNS;
        let idle_timeout = (7 * 24 * 3600) / 3; // 7 days of 3-second Drand kyns

        let mut expired_names = Vec::new();

        for (name, record) in &self.reveals_by_name {
            match record {
                kinetic_core::types::NameRecord::Standard(reveal) => {
                    let age = current_kyn.saturating_sub(reveal.kyn);
                    if age > max_age_kyns {
                        expired_names.push(name.clone());
                        continue;
                    }

                    let last_hb = self
                        .last_heartbeats_by_name
                        .get(name)
                        .copied()
                        .unwrap_or(reveal.kyn);
                    let hb_age = current_kyn.saturating_sub(last_hb);

                    if !kinetic_core::types::protocol::requires_heartbeat(name) {
                        continue;
                    }

                    if hb_age > idle_timeout {
                        expired_names.push(name.clone());
                    }
                }
                kinetic_core::types::NameRecord::Prime { granted_at, .. } => {
                    let grant_kyn = kinetic_core::types::clock::unix_time_to_kyn(
                        *granted_at,
                        kinetic_core::constants::DRAND_GENESIS_TIME,
                        kinetic_core::constants::DRAND_PERIOD,
                    );
                    let last_hb = self
                        .last_heartbeats_by_name
                        .get(name)
                        .copied()
                        .unwrap_or(grant_kyn);
                    let hb_age = current_kyn.saturating_sub(last_hb);

                    if hb_age > idle_timeout {
                        expired_names.push(name.clone());
                    }
                }
                kinetic_core::types::NameRecord::Infra { .. } => {
                    // Infrastructure names are fully immortal and do not expire.
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
                kinetic_core::constants::NETWORK_SALT,
            );
            for key_bytes in keys {
                let k = kad::RecordKey::new(&key_bytes);
                let mut sled_key = Vec::with_capacity(11 + k.as_ref().len());
                sled_key.extend_from_slice(b"kad_record:");
                sled_key.extend_from_slice(k.as_ref());
                keys_to_delete.push(sled_key);
                self.inner.remove(&k);
            }

            let hb_keys = kinetic_core::types::derive_heartbeat_keys(
                &name,
                kinetic_core::constants::NETWORK_SALT,
            );
            for key_bytes in hb_keys {
                let k = kad::RecordKey::new(&key_bytes);
                let mut sled_key = Vec::with_capacity(11 + k.as_ref().len());
                sled_key.extend_from_slice(b"kad_record:");
                sled_key.extend_from_slice(k.as_ref());
                keys_to_delete.push(sled_key);
                self.inner.remove(&k);
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

    pub(crate) fn get_fallback(
        &mut self,
        name: &str,
    ) -> Option<kinetic_core::types::NameRecord> {
        if let Some(r) = self.reveals_by_name.get(name) {
            return Some(r.clone());
        }
        let key = [crate::store::constants::KRS_REVEAL_PREFIX, name.as_bytes()].concat();
        if let Ok(Some(bytes)) = self.storage.get(&key)
            && let Ok(record) = serde_json::from_slice::<kinetic_core::types::NameRecord>(&bytes)
        {
            self.reveals_by_name.put(name.to_string(), record.clone());
            return Some(record);
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
    pub fn put(&mut self, r: kad::Record) -> Result<(), KineticStoreError> {
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
    pub fn put_verified(&mut self, r: kad::Record) -> Result<(), KineticStoreError> {
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
                error_code = "KIN-VAL-001",
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
                            .put(&key, &self.current_kyn.to_be_bytes());
                        return self
                            .inner
                            .put(r)
                            .map_err(|_| KineticStoreError::InternalStoreError);
                    }
                    Err(e) => {
                        let err = KineticStoreError::SchemaValidationError;
                        tracing::warn!(error_code = "KIN-VAL-004", severity = ?err.severity(), "Failed to parse Commitment schema: {}", e);
                        return Err(err);
                    }
                }
            } else if parsed.get("vdf_proof").is_some() || parsed.get("granted_at").is_some() {
                match serde_json::from_value::<kinetic_core::types::NameRecord>(parsed) {
                    Ok(record) => {
                        tracing::debug!(
                            "KineticRecordStore::put parsed NameRecord for {}",
                            record.name()
                        );
                        self.handle_put_record(&record, skip_reveal_verify)?;
                    }
                    Err(e) => {
                        let err = KineticStoreError::SchemaValidationError;
                        tracing::warn!(error_code = "KIN-VAL-005", severity = ?err.severity(), "Failed to parse NameRecord schema: {}", e);
                        return Err(err);
                    }
                }
            } else if parsed.get("latest_kyn").is_some() {
                match serde_json::from_value::<kinetic_core::types::Heartbeat>(parsed) {
                    Ok(heartbeat) => {
                        tracing::trace!(
                            "KineticRecordStore::put parsed Heartbeat for {}",
                            heartbeat.name
                        );
                        self.handle_process_heartbeat(&heartbeat)?;
                    }
                    Err(e) => {
                        let err = KineticStoreError::SchemaValidationError;
                        tracing::warn!(error_code = "KIN-VAL-006", severity = ?err.severity(), "Failed to parse Heartbeat schema: {}", e);
                        return Err(err);
                    }
                }
            } else if parsed.get("delegation_signature").is_some() {
                match serde_json::from_value::<kinetic_core::types::AuthorizedKid>(parsed) {
                    Ok(auth_kid) => {
                        let active_record = self.get_fallback(&auth_kid.name);
                        let existing_record = self.inner.get(&r.key);
                        super::verification::verify_authorized_kid(
                            &auth_kid,
                            active_record.as_ref(),
                            existing_record.as_ref(),
                        )?;
                    }
                    Err(e) => {
                        let err = KineticStoreError::SchemaValidationError;
                        tracing::warn!(error_code = "KIN-VAL-007", severity = ?err.severity(), "Failed to parse AuthorizedKid schema: {}", e);
                        return Err(err);
                    }
                }
            } else if parsed.get("manifest").is_some() {
                match serde_json::from_value::<kinetic_core::types::AuthorizedManifest>(parsed) {
                    Ok(auth_manifest) => {
                        let active_record = self.get_fallback(&auth_manifest.name);
                        let existing_record = self.inner.get(&r.key);
                        super::verification::verify_authorized_manifest(
                            &auth_manifest,
                            active_record.as_ref(),
                            existing_record.as_ref(),
                        )?;
                    }
                    Err(e) => {
                        let err = KineticStoreError::SchemaValidationError;
                        tracing::warn!(error_code = "KIN-VAL-008", severity = ?err.severity(), "Failed to parse AuthorizedManifest schema: {}", e);
                        return Err(err);
                    }
                }
            } else if parsed.get("host_id").is_some() {
                match serde_json::from_value::<kinetic_core::types::HostRoutingRecord>(parsed) {
                    Ok(host_route) => {
                        match crate::store::verification::verify_host_routing_record(
                            &host_route,
                            self.current_kyn,
                        ) {
                            Ok(()) => {
                                tracing::info!(
                                    "KineticRecordStore::put accepted verified HostRoutingRecord for {}",
                                    host_route.host_id
                                );
                            }
                            Err(err) => {
                                tracing::warn!(error_code = "KIN-VAL-010", host_id = %host_route.host_id, severity = ?err.severity(), "Rejecting HostRoutingRecord: {}", err);
                                return Err(err);
                            }
                        }
                    }
                    Err(e) => {
                        let err = KineticStoreError::SchemaValidationError;
                        tracing::warn!(error_code = "KIN-VAL-009", severity = ?err.severity(), "Failed to parse HostRoutingRecord schema: {}", e);
                        return Err(err);
                    }
                }
            } else {
                let err = KineticStoreError::UnknownRecordType;
                tracing::warn!(
                    error_code = "KIN-VAL-003",
                    severity = ?err.severity(),
                    "Rejecting Kademlia record: {}", err
                );
                return Err(err);
            }
        } else {
            let err = KineticStoreError::MalformedJson;
            tracing::warn!(
                error_code = "KIN-VAL-002",
                severity = ?err.severity(),
                "Rejecting Kademlia record due to malformed JSON: {}", err
            );
            return Err(err);
        }

        let mut sled_key = Vec::with_capacity(11 + r.key.as_ref().len());
        sled_key.extend_from_slice(b"kad_record:");
        sled_key.extend_from_slice(r.key.as_ref());
        let _ = self.storage.put(&sled_key, &r.value);
        self.inner
            .put(r)
            .map_err(|_| KineticStoreError::InternalStoreError)
    }
}

impl kad::store::RecordStore for KineticRecordStore {
    type RecordsIter<'a> = <kad::store::MemoryStore as kad::store::RecordStore>::RecordsIter<'a>;
    type ProvidedIter<'a> = <kad::store::MemoryStore as kad::store::RecordStore>::ProvidedIter<'a>;

    fn get(&self, k: &kad::RecordKey) -> Option<std::borrow::Cow<'_, kad::Record>> {
        self.inner.get(k)
    }

    fn put(&mut self, r: kad::Record) -> kad::store::Result<()> {
        self.put(r).map_err(|e| e.into())
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
    use kinetic_storage::KineticStorage;
    use libp2p::identity::Keypair;
    use tempfile::tempdir;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_store_rejects_garbage() {
        let dir = tempdir().unwrap();
        let sled_storage = Arc::new(KineticStorage::new(dir.path()).unwrap());
        let keypair = Keypair::generate_ed25519();
        let peer_id = PeerId::from(keypair.public());

        let vdf_engine: std::sync::Arc<dyn kinetic_core::traits::VdfEngine> =
            std::sync::Arc::new(kinetic_vdf_rsa::RsaVdfEngine::new());
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
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_pruning_idle_names() {
        let dir = tempdir().unwrap();
        let sled_storage = Arc::new(KineticStorage::new(dir.path()).unwrap());
        let keypair = Keypair::generate_ed25519();
        let peer_id = PeerId::from(keypair.public());
        let vdf_engine: std::sync::Arc<dyn kinetic_core::traits::VdfEngine> =
            std::sync::Arc::new(kinetic_vdf_rsa::RsaVdfEngine::new());

        let mut store = KineticRecordStore::new(
            peer_id,
            sled_storage.clone(),
            1000000, // Very high drand kyn
            NonZeroUsize::new(100).unwrap(),
            100,
            vdf_engine,
        );

        let name = "a.kin"; // Prime name, requires heartbeats
        let record = kinetic_core::types::NameRecord::Prime {
            name: name.to_string(),
            pubkey: vec![],
            granted_at: 0,
            payload: vec![],
            signature: vec![],
            authorization: None,
        };

        let record_bytes = serde_json::to_vec(&record).unwrap();
        let derived_keys =
            kinetic_core::types::derive_storage_keys(name, kinetic_core::constants::NETWORK_SALT);
        let kad_key = kad::RecordKey::new(&derived_keys[0]);

        let kad_record = kad::Record::new(kad_key.clone(), record_bytes);
        store.put_record_internal(kad_record, true).unwrap();

        assert!(store.get_fallback(name).is_some());

        store.current_kyn += 300000;
        store.prune();

        // Wait for async deletion task to run
        tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;

        // It should be pruned!
        assert!(store.reveals_by_name.get(name).is_none());
        use libp2p::kad::store::RecordStore;
        assert!(
            store.get(&kad_key).is_none(),
            "Zombie record RAM leak detected! Record still exists in MemoryStore!"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_pruning_exempt_names() {
        let dir = tempdir().unwrap();
        let sled_storage = Arc::new(KineticStorage::new(dir.path()).unwrap());
        let keypair = Keypair::generate_ed25519();
        let peer_id = PeerId::from(keypair.public());
        let vdf_engine: std::sync::Arc<dyn kinetic_core::traits::VdfEngine> =
            std::sync::Arc::new(kinetic_vdf_rsa::RsaVdfEngine::new());

        let mut store = KineticRecordStore::new(
            peer_id,
            sled_storage.clone(),
            1000000,
            NonZeroUsize::new(100).unwrap(),
            100,
            vdf_engine,
        );

        let name = "seed.kin"; // Exempt protocol name
        let record = kinetic_core::types::NameRecord::Infra {
            name: name.to_string(),
            pubkey: vec![],
            granted_at: 0,
            payload: vec![],
            signature: vec![],
            authorization: None,
        };

        let record_bytes = serde_json::to_vec(&record).unwrap();
        let derived_keys =
            kinetic_core::types::derive_storage_keys(name, kinetic_core::constants::NETWORK_SALT);
        let kad_key = kad::RecordKey::new(&derived_keys[0]);

        let kad_record = kad::Record::new(kad_key.clone(), record_bytes);
        store.put_record_internal(kad_record, true).unwrap();

        assert!(store.get_fallback(name).is_some());

        store.current_kyn += 300000;
        store.prune();

        tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;

        // It should NOT be pruned!
        assert!(store.get_fallback(name).is_some());
    }

    #[tokio::test]
    async fn test_orphaned_heartbeat_cleanup_on_boot() {
        let dir = tempfile::tempdir().unwrap();
        let storage: std::sync::Arc<dyn kinetic_core::traits::StorageEngine> =
            std::sync::Arc::new(KineticStorage::new(dir.path()).unwrap());

        let name = "orphan.kin";
        let hb_key = [crate::store::constants::KRS_HB_PREFIX, name.as_bytes()].concat();
        let kyn: u64 = 999;
        storage.put(&hb_key, &kyn.to_be_bytes()).unwrap();

        assert!(
            storage.get(&hb_key).unwrap().is_some(),
            "Heartbeat should exist in Sled"
        );

        let peer_id = libp2p::PeerId::from(libp2p::identity::Keypair::generate_ed25519().public());
        let vdf_engine: std::sync::Arc<dyn kinetic_core::traits::VdfEngine> =
            std::sync::Arc::new(kinetic_vdf_rsa::RsaVdfEngine::new());
        let store = KineticRecordStore::new(
            peer_id,
            storage.clone(),
            1000,
            std::num::NonZeroUsize::new(100).unwrap(),
            100,
            vdf_engine,
        );

        assert!(
            !store.last_heartbeats_by_name.contains_key(name),
            "Should not be in RAM"
        );
        assert!(
            storage.get(&hb_key).unwrap().is_none(),
            "Should be purged from Sled"
        );
    }

    #[tokio::test]
    async fn test_80kb_payload_capacity() {
        let dir = tempfile::tempdir().unwrap();
        let storage: std::sync::Arc<dyn kinetic_core::traits::StorageEngine> =
            std::sync::Arc::new(KineticStorage::new(dir.path()).unwrap());
        let peer_id = libp2p::PeerId::from(libp2p::identity::Keypair::generate_ed25519().public());
        let vdf_engine: std::sync::Arc<dyn kinetic_core::traits::VdfEngine> =
            std::sync::Arc::new(kinetic_vdf_rsa::RsaVdfEngine::new());

        let mut store = KineticRecordStore::new(
            peer_id,
            storage,
            1000,
            std::num::NonZeroUsize::new(100).unwrap(),
            100,
            vdf_engine,
        );

        let large_payload = vec![0u8; 34000];
        let record = kinetic_core::types::NameRecord::Prime {
            name: "large.kin".to_string(),
            pubkey: vec![],
            granted_at: 0,
            payload: large_payload,
            signature: vec![],
            authorization: None,
        };

        let record_bytes = serde_json::to_vec(&record).unwrap();
        let key = libp2p::kad::RecordKey::new(&"dummy");
        let kad_record = libp2p::kad::Record::new(key, record_bytes.clone());

        let res = store.put_record_internal(kad_record, true);
        assert!(res.is_ok(), "Error: {:?}", res.unwrap_err());
    }

    #[tokio::test]
    async fn test_schema_and_malformed_json_rejection() {
        let dir = tempfile::tempdir().unwrap();
        let storage: std::sync::Arc<dyn kinetic_core::traits::StorageEngine> =
            std::sync::Arc::new(KineticStorage::new(dir.path()).unwrap());
        let peer_id = libp2p::PeerId::from(libp2p::identity::Keypair::generate_ed25519().public());
        let vdf_engine: std::sync::Arc<dyn kinetic_core::traits::VdfEngine> =
            std::sync::Arc::new(kinetic_vdf_rsa::RsaVdfEngine::new());

        let mut store = KineticRecordStore::new(
            peer_id,
            storage,
            100,
            std::num::NonZeroUsize::new(100).unwrap(),
            100,
            vdf_engine,
        );

        let bad_bytes = vec![0, 255, 0, 128];
        let kad_record_bad =
            libp2p::kad::Record::new(libp2p::kad::RecordKey::new(&"key1"), bad_bytes);
        let res1 = store.put(kad_record_bad);
        assert!(matches!(
            res1.unwrap_err(),
            crate::error::KineticStoreError::MalformedJson
        ));

        let schema_error_json = r#"{"hash": "this_is_a_string_not_an_array"}"#;
        let kad_record_schema = libp2p::kad::Record::new(
            libp2p::kad::RecordKey::new(&"key2"),
            schema_error_json.as_bytes().to_vec(),
        );
        let res2 = store.put(kad_record_schema);
        assert!(matches!(
            res2.unwrap_err(),
            crate::error::KineticStoreError::SchemaValidationError
        ));
    }
}
