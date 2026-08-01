//! Handler logic for processing domain reveals and liveness heartbeats.

use crate::error::KineticStoreError;
use crate::store::constants::*;
use crate::store::core::KineticRecordStore;

impl KineticRecordStore {
    pub(crate) fn handle_record(
        &mut self,
        record: &kinetic_core::types::DomainRecord,
        skip_verify: bool,
    ) -> Result<(), KineticStoreError> {
        let total_paused_rounds =
            if let Ok(state) = kinetic_core::governance::GLOBAL_GOVERNANCE_STATE.lock() {
                state.total_paused_rounds
            } else {
                0
            };

        let reveal_ref = match record {
            kinetic_core::types::DomainRecord::Standard(r) => Some(r),
            kinetic_core::types::DomainRecord::Premium { .. } => None,
        };

        if let Some(reveal) = reveal_ref {
            let effective_age = self
                .current_drand_round
                .saturating_sub(reveal.drand_pulse)
                .saturating_sub(total_paused_rounds);

            if effective_age > kinetic_core::types::RESQUARING_EPOCH_ROUNDS {
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
                    self.current_drand_round,
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
                let last_hb_round = self
                    .last_heartbeats_by_name
                    .get(record.name())
                    .copied()
                    .unwrap_or_else(|| reveal_ref.map_or(0, |r| r.drand_pulse));

                let hb_age = self.current_drand_round.saturating_sub(last_hb_round);

                let (existing_reveal, new_reveal) = match (existing_record, record) {
                    (
                        kinetic_core::types::DomainRecord::Standard(existing),
                        kinetic_core::types::DomainRecord::Standard(new),
                    ) => (existing, new),
                    _ => {
                        let err = KineticStoreError::TieBroken; // Premium domains cannot be stolen or steal
                        err.log_warning("KIN-STORE-004", record.name(), "Rejecting Steal:");
                        return Err(err);
                    }
                };

                let drand_rand =
                    hex::decode(&new_reveal.drand_randomness).unwrap_or_else(|_| vec![0u8; 32]);
                let base_diff = consensus_math.required_iterations(&new_reveal.name, &drand_rand);
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
                    tracing::info!("Valid Steal Reveal for {}! Overwriting previous owner (idle for {} rounds).", new_reveal.name, hb_age);

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
                }
            } else {
                let existing_pulse = match &existing_record {
                    kinetic_core::types::DomainRecord::Standard(r) => r.drand_pulse,
                    kinetic_core::types::DomainRecord::Premium { .. } => 0,
                };
                let new_pulse = reveal_ref.map_or(0, |r| r.drand_pulse);

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
                    if !skip_verify
                        && !dev_mode
                        && record.verify_signature(kinetic_core::constants::NETWORK_ID).is_err()
                    {
                        let err = KineticStoreError::InvalidSignature;
                        err.log_warning(
                            "KIN-STORE-015",
                            record.name(),
                            "Rejecting updated record due to invalid signature:",
                        );
                        return Err(err);
                    }
                }
            }
        } else {
            // New record, verify signature
            let dev_mode = kinetic_core::config::is_dev_mode();
            if !skip_verify
                && !dev_mode
                && record.verify_signature(kinetic_core::constants::NETWORK_ID).is_err()
            {
                let err = KineticStoreError::InvalidSignature;
                err.log_warning(
                    "KIN-STORE-015",
                    record.name(),
                    "Rejecting new record due to invalid signature:",
                );
                return Err(err);
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

        let current_round = std::cmp::max(
            self.current_drand_round,
            reveal_ref.map_or(0, |r| r.drand_pulse),
        );
        self.last_heartbeats_by_name
            .insert(name.to_string(), current_round);
        let hb_key = [KRS_HB_PREFIX, name.as_bytes()].concat();
        writes_to_perform.push((hb_key, current_round.to_be_bytes().to_vec()));

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

        if heartbeat.latest_drand_pulse == existing_pulse {
            // Normal duplicate via DHT gossip, ignore it silently to prevent log spam and CPU waste
            return Ok(());
        }

        if heartbeat.latest_drand_pulse < existing_pulse {
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
        use ml_dsa::KeyInit;
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

        use ml_dsa::signature::Verifier;
        if pubkey.verify(&signable, &sig).is_err() {
            let err = KineticStoreError::InvalidSignature;
            err.log_warning("KIN-STORE-015", &heartbeat.name, "Rejecting Heartbeat:");
            return Err(err);
        }

        if heartbeat.latest_drand_pulse > self.current_drand_round + 2 {
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
            .insert(heartbeat.name.clone(), heartbeat.latest_drand_pulse);
        let hb_key = [KRS_HB_PREFIX, heartbeat.name.as_bytes()].concat();
        let hb_val = heartbeat.latest_drand_pulse.to_be_bytes().to_vec();

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
