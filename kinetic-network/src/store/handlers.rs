use crate::error::KineticStoreError;
use crate::store::constants::*;
use crate::store::core::KineticRecordStore;
use kinetic_core::traits::StorageEngine;


impl KineticRecordStore {
    pub(crate) fn handle_reveal(
        &mut self,
        reveal: &kinetic_core::types::Reveal,
    ) -> Result<(), KineticStoreError> {
        // Finding 3: Use the shared constant instead of a hardcoded magic number.
        if self.current_drand_round.saturating_sub(reveal.drand_pulse)
            > kinetic_core::types::RESQUARING_EPOCH_ROUNDS
        {
            let age = self.current_drand_round.saturating_sub(reveal.drand_pulse);
            let err = KineticStoreError::VdfExpired { age };
            err.log_warning("KIN-STORE-001", &reveal.name, "Rejecting Reveal:");
            return Err(err.into());
        }

        if let Err(e) = super::verification::verify_reveal(
            reveal,
            &self.storage,
            self.current_drand_round,
        ) {
            e.log_warning("KIN-STORE-002", &reveal.name, "Rejecting Reveal:");
            return Err(e.into());
        }

        if let Some(existing_reveal) = self.reveals_by_name.get(&reveal.name) {
            if existing_reveal.pubkey != reveal.pubkey {
                let consensus_math = kinetic_core::consensus_math::ConsensusParams::default();
                let last_hb_round = self
                    .last_heartbeats_by_name
                    .get(&reveal.name)
                    .copied()
                    .unwrap_or(reveal.drand_pulse);



                let hb_age = self.current_drand_round.saturating_sub(last_hb_round);
                let base_diff = consensus_math.required_iterations(
                    &reveal.name,
                    reveal.drand_pulse,
                );
                let steal_threshold = consensus_math.steal_difficulty(base_diff, hb_age);

                // Case 121: Deterministic Tie-Breaking
                if reveal.iterations == existing_reveal.iterations && hb_age < 100 {
                    if reveal.pubkey > existing_reveal.pubkey {
                        let err = KineticStoreError::TieBroken;
                        err.log_warning("KIN-STORE-004", &reveal.name, "Rejecting Steal Reveal:");
                        return Err(err.into());
                    } else {
                        tracing::info!("Valid Steal Reveal for {}! Tie-break won!", reveal.name);
                    }
                } else if reveal.iterations < steal_threshold {
                    let err = KineticStoreError::InsufficientIterations;
                    err.log_warning("KIN-STORE-005", &reveal.name, "Rejecting Steal Reveal:");
                    return Err(err.into());
                } else {
                    tracing::info!("Valid Steal Reveal for {}! Overwriting previous owner (idle for {} rounds).", reveal.name, hb_age);
                    
                    // Cleanup orphaned keys from previous owner
                    let keys = kinetic_core::types::derive_storage_keys(&reveal.name);
                    for key_bytes in keys {
                        let k = libp2p::kad::RecordKey::new(&key_bytes);
                        let mut sled_key = Vec::with_capacity(11 + k.as_ref().len());
                        sled_key.extend_from_slice(b"kad_record:");
                        sled_key.extend_from_slice(k.as_ref());
                        let _ = self.storage.delete(&sled_key);
                    }
                    let hb_keys = kinetic_core::types::derive_heartbeat_keys(&reveal.name);
                    for key_bytes in hb_keys {
                        let k = libp2p::kad::RecordKey::new(&key_bytes);
                        let mut sled_key = Vec::with_capacity(11 + k.as_ref().len());
                        sled_key.extend_from_slice(b"kad_record:");
                        sled_key.extend_from_slice(k.as_ref());
                        let _ = self.storage.delete(&sled_key);
                    }
                }
            }
        }

        self.reveals_by_name
            .put(reveal.name.clone(), reveal.clone());
        let reveal_key = [KRS_REVEAL_PREFIX, reveal.name.as_bytes()].concat();
        
        let mut writes_to_perform = Vec::new();

        if let Ok(bytes) = serde_json::to_vec(&reveal) {
            writes_to_perform.push((reveal_key, bytes));
        }

        if let Some(spent) = reveal.points_spent {
            if spent > 0 {
                let mut balance_key = Vec::with_capacity(crate::store::constants::KRS_POINTS_PREFIX.len() + reveal.pubkey.len());
                balance_key.extend_from_slice(crate::store::constants::KRS_POINTS_PREFIX);
                balance_key.extend_from_slice(&reveal.pubkey);
                let mut balance = match self.storage.get(&balance_key) {
                    Ok(Some(bytes)) if bytes.len() == 8 => u64::from_be_bytes(bytes[..8].try_into().unwrap_or([0u8; 8])),
                    _ => 0,
                };
                balance = balance.saturating_sub(spent);
                writes_to_perform.push((balance_key, balance.to_be_bytes().to_vec()));
                tracing::info!(
                    "Deducted {} points from {}. New balance: {}",
                    spent,
                    hex::encode(&reveal.pubkey),
                    balance
                );
            }
        }

        if let Some(miner_pk) = &reveal.miner_pubkey {
            let mut balance_key = Vec::with_capacity(crate::store::constants::KRS_POINTS_PREFIX.len() + miner_pk.len());
            balance_key.extend_from_slice(crate::store::constants::KRS_POINTS_PREFIX);
            balance_key.extend_from_slice(miner_pk);
            let mut balance = match self.storage.get(&balance_key) {
                Ok(Some(bytes)) if bytes.len() == 8 => u64::from_be_bytes(bytes[..8].try_into().unwrap_or([0u8; 8])),
                _ => 0,
            };
            balance = balance.saturating_add(reveal.iterations);
            writes_to_perform.push((balance_key, balance.to_be_bytes().to_vec()));
            tracing::info!(
                "Awarded {} points to miner {}. New balance: {}",
                reveal.iterations,
                hex::encode(miner_pk),
                balance
            );
        }

        let now = web_time::Instant::now();
        self.accepted_reveals_timestamps.push_back(now);
        while let Some(t) = self.accepted_reveals_timestamps.front() {
            if now.duration_since(*t) > web_time::Duration::from_secs(3600) {
                self.accepted_reveals_timestamps.pop_front();
            } else {
                break;
            }
        }
        if self.accepted_reveals_timestamps.len() > self.max_reveals_per_hour {
            let err = KineticStoreError::RateLimited;
            err.log_warning("KIN-STORE-022", &reveal.name, "Rejecting Reveal:");
            return Err(err.into());
        }

        let current_round = std::cmp::max(self.current_drand_round, reveal.drand_pulse);
        self.last_heartbeats_by_name
            .insert(reveal.name.clone(), current_round);
        let hb_key = [KRS_HB_PREFIX, reveal.name.as_bytes()].concat();
        writes_to_perform.push((hb_key, current_round.to_be_bytes().to_vec()));

        if !writes_to_perform.is_empty() {
            let storage = self.storage.clone();
            crate::event_loop::utils::spawn(async move {
                let _ = tokio::task::spawn_blocking(move || {
                    for (k, v) in writes_to_perform {
                        let _ = storage.put(&k, &v);
                    }
                }).await;
            });
        }

        Ok(())
    }



    pub(crate) fn handle_heartbeat(
        &mut self,
        heartbeat: &kinetic_core::types::Heartbeat,
    ) -> Result<(), KineticStoreError> {
        let existing_reveal = match self.reveals_by_name.get(&heartbeat.name) {
            Some(r) => r,
            None => {
                let err = KineticStoreError::RevealNotFound;
                err.log_warning("KIN-STORE-012", &heartbeat.name, "Rejecting Heartbeat:");
                return Err(err.into());
            }
        };

        let signable = heartbeat.signable_bytes();
        let pubkey = ed25519_dalek::VerifyingKey::try_from(existing_reveal.pubkey.as_slice())
            .map_err(|_| {
                let err = KineticStoreError::InvalidPublicKey;
                err.log_warning("KIN-STORE-013", &heartbeat.name, "Rejecting Heartbeat:");
                err
            })?;
        let sig = ed25519_dalek::Signature::from_slice(&heartbeat.signature).map_err(|_| {
            let err = KineticStoreError::MalformedSignature;
            err.log_warning("KIN-STORE-014", &heartbeat.name, "Rejecting Heartbeat:");
            err
        })?;

        use ed25519_dalek::Verifier;
        if pubkey.verify(&signable, &sig).is_err() {
            let err = KineticStoreError::InvalidSignature;
            err.log_warning("KIN-STORE-015", &heartbeat.name, "Rejecting Heartbeat:");
            return Err(err.into());
        }

        if heartbeat.latest_drand_pulse > self.current_drand_round + 2 {
            let err = KineticStoreError::StaleHeartbeat;
            err.log_warning("KIN-STORE-021", &heartbeat.name, "Rejecting Heartbeat: future-dated:");
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
            err.log_warning("KIN-STORE-020", &heartbeat.name, "Rejecting Heartbeat:");
            return Err(err.into());
        }

        self.last_heartbeats_by_name
            .insert(heartbeat.name.clone(), heartbeat.latest_drand_pulse);
        let hb_key = [KRS_HB_PREFIX, heartbeat.name.as_bytes()].concat();
        let hb_val = heartbeat.latest_drand_pulse.to_be_bytes().to_vec();
        
        let storage = self.storage.clone();
        crate::event_loop::utils::spawn(async move {
            let _ = tokio::task::spawn_blocking(move || {
                let _ = storage.put(&hb_key, &hb_val);
            }).await;
        });

        Ok(())
    }
}
