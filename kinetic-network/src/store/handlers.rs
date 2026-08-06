//! Handler logic for processing domain reveals and liveness heartbeats.

use crate::error::KineticStoreError;
use crate::store::constants::*;
use crate::store::core::KineticRecordStore;

impl KineticRecordStore {
    pub(crate) fn handle_record(
        &mut self,
        record: &kinetic_core::types::NameRecord,
        skip_verify: bool,
    ) -> Result<(), KineticStoreError> {
        let reveal_ref = match record {
            kinetic_core::types::NameRecord::Standard(r) => Some(r),
            kinetic_core::types::NameRecord::Premium { .. } => None,
        };

        if let Some(reveal) = reveal_ref {
            let paused_kyns =
                if let Ok(state) = kinetic_core::governance::GLOBAL_GOVERNANCE_STATE.lock() {
                    state.paused_kyns_since(reveal.drand_kyn)
                } else {
                    0
                };

            let effective_age = self
                .current_drand_kyn
                .saturating_sub(reveal.drand_kyn)
                .saturating_sub(paused_kyns);

            if effective_age > kinetic_core::types::RESQUARING_EPOCH_KYNS {
                let err = KineticStoreError::VdfExpired { age: effective_age };
                err.log_warning("KIN-STORE-001", record.name(), "Rejecting Record:");
                return Err(err);
            }
        }

        if !skip_verify {
            if let Some(reveal) = reveal_ref {
                if let Err(e) = super::verification::verify_reveal(
                    reveal,
                    &self.storage,
                    self.current_drand_kyn,
                    &self.vdf_engine,
                ) {
                    e.log_warning("KIN-STORE-002", record.name(), "Rejecting Reveal:");
                    return Err(e);
                }
            }
        }

        if let Some(existing_record) = self.get_record_with_fallback(record.name()) {
            if existing_record.pubkey() != record.pubkey() {
                let consensus_math = kinetic_core::consensus_math::ConsensusParams::default();
                let last_hb_kyn = self
                    .last_heartbeats_by_name
                    .get(record.name())
                    .copied()
                    .unwrap_or_else(|| reveal_ref.map_or(0, |r| r.drand_kyn));

                let hb_age = self.current_drand_kyn.saturating_sub(last_hb_kyn);

                let (existing_reveal, new_reveal) = match (existing_record, record) {
                    (
                        kinetic_core::types::NameRecord::Standard(existing),
                        kinetic_core::types::NameRecord::Standard(new),
                    ) => (existing, new),
                    _ => {
                        let err = KineticStoreError::TieBroken; // Premium domains cannot be stolen or steal
                        err.log_warning("KIN-STORE-004", record.name(), "Rejecting Steal:");
                        return Err(err);
                    }
                };

                let base_diff = consensus_math.required_iterations(&new_reveal.name);
                let steal_threshold = consensus_math.steal_difficulty(base_diff, hb_age);

                // Case 121: Deterministic Tie-Breaking
                if new_reveal.iterations == existing_reveal.iterations && hb_age < 100 {
                    let dist_new: Vec<u8> = new_reveal
                        .pubkey
                        .iter()
                        .zip(
                            new_reveal
                                .vdf_proof
                                .proof_bytes
                                .iter()
                                .chain(std::iter::once(&0))
                                .cycle(),
                        )
                        .map(|(&a, &b)| a ^ b)
                        .collect();

                    let dist_existing: Vec<u8> = existing_reveal
                        .pubkey
                        .iter()
                        .zip(
                            existing_reveal
                                .vdf_proof
                                .proof_bytes
                                .iter()
                                .chain(std::iter::once(&0))
                                .cycle(),
                        )
                        .map(|(&a, &b)| a ^ b)
                        .collect();

                    if dist_new > dist_existing {
                        let err = KineticStoreError::TieBroken;
                        err.log_warning(
                            "KIN-STORE-004",
                            &new_reveal.name,
                            "Rejecting Steal Reveal:",
                        );
                        return Err(err);
                    } else {
                        tracing::info!(
                            "Valid Steal Reveal for {}! Tie-break won!",
                            new_reveal.name
                        );
                    }
                } else if new_reveal.iterations < steal_threshold {
                    let err = KineticStoreError::InsufficientIterations;
                    err.log_warning("KIN-STORE-005", &new_reveal.name, "Rejecting Steal Reveal:");
                    return Err(err);
                } else {
                    tracing::info!("Valid Steal Reveal for {}! Overwriting previous owner (idle for {} kyns).", new_reveal.name, hb_age);
                }

                // Cleanup orphaned keys from previous owner
                    let keys = kinetic_core::types::derive_storage_keys(
                        &new_reveal.name,
                        kinetic_core::constants::NETWORK_ID,
                    );
                    for key_bytes in keys {
                        let k = libp2p::kad::RecordKey::new(&key_bytes);
                        let mut sled_key = Vec::with_capacity(11 + k.as_ref().len());
                        sled_key.extend_from_slice(b"kad_record:");
                        sled_key.extend_from_slice(k.as_ref());
                        let _ = self.storage.delete(&sled_key);
                    }
                    let hb_keys = kinetic_core::types::derive_heartbeat_keys(
                        &new_reveal.name,
                        kinetic_core::constants::NETWORK_ID,
                    );
                    for key_bytes in hb_keys {
                        let k = libp2p::kad::RecordKey::new(&key_bytes);
                        let mut sled_key = Vec::with_capacity(11 + k.as_ref().len());
                        sled_key.extend_from_slice(b"kad_record:");
                        sled_key.extend_from_slice(k.as_ref());
                        let _ = self.storage.delete(&sled_key);
                    }
            } else {
                let existing_pulse = match &existing_record {
                    kinetic_core::types::NameRecord::Standard(r) => r.drand_kyn,
                    kinetic_core::types::NameRecord::Premium { .. } => 0,
                };
                let new_pulse = reveal_ref.map_or(0, |r| r.drand_kyn);

                if new_pulse < existing_pulse {
                    let err = KineticStoreError::StaleReveal;
                    err.log_warning("KIN-STORE-023", record.name(), "Rejecting Replayed Reveal:");
                    return Err(err);
                } else if record.payload() == existing_record.payload()
                    && record.signature() == existing_record.signature()
                {
                    return Ok(());
                } else {
                    // Updating payload of existing domain. Verify the updated payload signature!
                    let dev_mode = kinetic_core::config::is_dev_mode();
                    if !skip_verify && !dev_mode {
                        if let Err(e) = record.verify_signature(kinetic_core::constants::NETWORK_ID) {
                            let err = match e {
                                kinetic_types::vdf::VdfVerifyError::DelegatedCapabilityMissing => KineticStoreError::DelegatedCapabilityMissing,
                                kinetic_types::vdf::VdfVerifyError::DelegatedAuthorizationInvalid => KineticStoreError::DelegatedAuthorizationInvalid,
                                _ => KineticStoreError::InvalidSignature,
                            };
                            err.log_warning(
                                "KIN-STORE-015",
                                record.name(),
                                "Rejecting updated record due to invalid signature:",
                            );
                            return Err(err);
                        }
                    }
                }
            }
        } else {
            // New record, verify signature
            let dev_mode = kinetic_core::config::is_dev_mode();
            if !skip_verify && !dev_mode {
                if let Err(e) = record.verify_signature(kinetic_core::constants::NETWORK_ID) {
                    let err = match e {
                        kinetic_types::vdf::VdfVerifyError::DelegatedCapabilityMissing => KineticStoreError::DelegatedCapabilityMissing,
                        kinetic_types::vdf::VdfVerifyError::DelegatedAuthorizationInvalid => KineticStoreError::DelegatedAuthorizationInvalid,
                        _ => KineticStoreError::InvalidSignature,
                    };
                    err.log_warning(
                        "KIN-STORE-015",
                        record.name(),
                        "Rejecting new record due to invalid signature:",
                    );
                    return Err(err);
                }
            }
        }

        let now = web_time::Instant::now();
        let name = record.name();
        if !self.accepted_reveals_timestamps.contains(name) {
            self.accepted_reveals_timestamps
                .put(name.to_string(), std::collections::VecDeque::new());
        }
        let deque = self.accepted_reveals_timestamps.get_mut(name).unwrap();
        while let Some(t) = deque.front() {
            if now.duration_since(*t) > web_time::Duration::from_secs(3600) {
                deque.pop_front();
            } else {
                break;
            }
        }
        if deque.len() >= self.max_reveals_per_hour {
            let err = KineticStoreError::RateLimited;
            err.log_warning("KIN-STORE-022", name, "Rejecting Reveal:");
            return Err(err);
        }
        deque.push_back(now);

        if let Some((evicted_name, _)) = self.reveals_by_name.push(name.to_string(), record.clone())
        {
            if evicted_name != name {
                self.last_heartbeats_by_name.remove(&evicted_name);
            }
        }
        let reveal_key = [KRS_REVEAL_PREFIX, name.as_bytes()].concat();

        let mut writes_to_perform = Vec::new();

        if let Ok(bytes) = serde_json::to_vec(&record) {
            writes_to_perform.push((reveal_key, bytes));
        }

        let current_kyn = std::cmp::max(
            self.current_drand_kyn,
            reveal_ref.map_or(0, |r| r.drand_kyn),
        );
        self.last_heartbeats_by_name
            .insert(name.to_string(), current_kyn);
        let hb_key = [KRS_HB_PREFIX, name.as_bytes()].concat();
        writes_to_perform.push((hb_key, current_kyn.to_be_bytes().to_vec()));

        if !writes_to_perform.is_empty() {
            let storage = self.storage.clone();
            crate::event_loop::utils::spawn(async move {
                let _ = crate::event_loop::utils::spawn_blocking(move || {
                    for (k, v) in writes_to_perform {
                        let _ = storage.put(&k, &v);
                    }
                })
                .await;
            });
        }

        Ok(())
    }

    pub(crate) fn handle_heartbeat(
        &mut self,
        heartbeat: &kinetic_core::types::Heartbeat,
    ) -> Result<(), KineticStoreError> {
        // OPTIMIZATION: Check for duplicates or stale heartbeats before doing any expensive ML-DSA signature verification
        let existing_pulse = self
            .last_heartbeats_by_name
            .get(&heartbeat.name)
            .copied()
            .unwrap_or(0);

        if heartbeat.latest_drand_kyn == existing_pulse {
            // Normal duplicate via DHT gossip, ignore it silently to prevent log spam and CPU waste
            return Ok(());
        }

        if heartbeat.latest_drand_kyn < existing_pulse {
            let err = KineticStoreError::StaleHeartbeat;
            err.log_warning("KIN-STORE-020", &heartbeat.name, "Rejecting Heartbeat:");
            return Err(err);
        }

        let existing_record = match self.get_record_with_fallback(&heartbeat.name) {
            Some(r) => r,
            None => {
                let err = KineticStoreError::RevealNotFound;
                err.log_warning("KIN-STORE-012", &heartbeat.name, "Rejecting Heartbeat:");
                return Err(err);
            }
        };

        let signable = heartbeat.signable_bytes(kinetic_core::constants::NETWORK_ID);
        use ml_dsa::signature::Verifier;
        use ml_dsa::KeyInit;

        let is_valid_signature = if let Some(auth) = &heartbeat.authorization {
            let primary_pubkey = ml_dsa::VerifyingKey::<ml_dsa::MlDsa65>::new_from_slice(existing_record.pubkey())
                .map_err(|_| {
                    let err = KineticStoreError::InvalidPublicKey;
                    err.log_warning("KIN-STORE-013", &heartbeat.name, "Rejecting Heartbeat:");
                    err
                })?;
            
            let auth_signable = auth.signable_bytes(kinetic_core::constants::NETWORK_ID);
            let auth_sig = ml_dsa::Signature::<ml_dsa::MlDsa65>::try_from(auth.owner_signature.as_slice())
                .map_err(|_| {
                    let err = KineticStoreError::DelegatedAuthorizationInvalid;
                    err.log_warning("KIN-STORE-023", &heartbeat.name, "Rejecting Heartbeat:");
                    err
                })?;
            
            if primary_pubkey.verify(&auth_signable, &auth_sig).is_err() {
                let err = KineticStoreError::DelegatedAuthorizationInvalid;
                err.log_warning("KIN-STORE-023", &heartbeat.name, "Rejecting Heartbeat:");
                return Err(err);
            }
            
            let has_cap = auth.manifest.services.iter().any(|s| s.service_type == "kinetic.capability.heartbeat");
            if !has_cap {
                let err = KineticStoreError::DelegatedCapabilityMissing;
                err.log_warning("KIN-STORE-022", &heartbeat.name, "Rejecting Heartbeat:");
                return Err(err);
            }
            
            let kid_doc = auth.kid_doc.as_ref().ok_or_else(|| {
                let err = KineticStoreError::DelegatedAuthorizationInvalid;
                err.log_warning("KIN-STORE-023", &heartbeat.name, "Rejecting Heartbeat:");
                err
            })?;
            
            let sig = ml_dsa::Signature::<ml_dsa::MlDsa65>::try_from(heartbeat.signature.as_slice())
                .map_err(|_| {
                    let err = KineticStoreError::MalformedSignature;
                    err.log_warning("KIN-STORE-014", &heartbeat.name, "Rejecting Heartbeat:");
                    err
                })?;
            
            let mut verified = false;
            for ck in &kid_doc.controller_keys {
                use base64::{engine::general_purpose::URL_SAFE_NO_PAD as b64_url, Engine};
                if ck.key_type == "ML-DSA-65" {
                    if let Ok(pk_bytes) = b64_url.decode(&ck.public_key) {
                        if let Ok(vk) = ml_dsa::VerifyingKey::<ml_dsa::MlDsa65>::new_from_slice(&pk_bytes) {
                            if vk.verify(&signable, &sig).is_ok() {
                                verified = true;
                                break;
                            }
                        }
                    }
                }
            }
            verified
        } else {
            let pubkey =
                ml_dsa::VerifyingKey::<ml_dsa::MlDsa65>::new_from_slice(existing_record.pubkey())
                    .map_err(|_| {
                        let err = KineticStoreError::InvalidPublicKey;
                        err.log_warning("KIN-STORE-013", &heartbeat.name, "Rejecting Heartbeat:");
                        err
                    })?;
            let sig = ml_dsa::Signature::<ml_dsa::MlDsa65>::try_from(heartbeat.signature.as_slice())
                .map_err(|_| {
                    let err = KineticStoreError::MalformedSignature;
                    err.log_warning("KIN-STORE-014", &heartbeat.name, "Rejecting Heartbeat:");
                    err
                })?;
            
            pubkey.verify(&signable, &sig).is_ok()
        };

        if !is_valid_signature {
            let err = KineticStoreError::InvalidSignature;
            err.log_warning("KIN-STORE-015", &heartbeat.name, "Rejecting Heartbeat:");
            return Err(err);
        }

        if heartbeat.latest_drand_kyn > self.current_drand_kyn + 2 {
            let err = KineticStoreError::StaleHeartbeat;
            err.log_warning(
                "KIN-STORE-021",
                &heartbeat.name,
                "Rejecting Heartbeat: future-dated:",
            );
            return Err(err);
        }

        // Monotonicity check already performed at the top of the function.

        self.last_heartbeats_by_name
            .insert(heartbeat.name.clone(), heartbeat.latest_drand_kyn);
        let hb_key = [KRS_HB_PREFIX, heartbeat.name.as_bytes()].concat();
        let hb_val = heartbeat.latest_drand_kyn.to_be_bytes().to_vec();

        let storage = self.storage.clone();
        crate::event_loop::utils::spawn(async move {
            let _ = crate::event_loop::utils::spawn_blocking(move || {
                let _ = storage.put(&hb_key, &hb_val);
            })
            .await;
        });

        Ok(())
    }
}
