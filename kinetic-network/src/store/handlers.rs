//! Handler logic for processing apex name reveals, commitments, and liveness heartbeats.
//!
//! ## The State Machine Transition Rules
//! This module houses `handle_put_record`, the most complex state transition function
//! in the Kinetic DHT. It enforces the economic and cryptographic rules of namespace
//! acquisition without relying on a global blockchain ledger.
//!
//! ## Core Enforcement Mechanics
//! - **Commit-Reveal Timelocks:** Enforces that a valid Commitment (hash) existed
//!   in the DHT for at least N network kyns before accepting the plaintext Reveal.
//!   This prevents front-running and namespace snipping by malicious routing peers.
//! - **Loyalty Discounts:** Analyzes the `previous_proof` attached to a Reveal.
//!   If a user has continuously maintained their namespace by chaining proofs over
//!   months, this module automatically calculates a drastic reduction in the required
//!   VDF (Verifiable Delay Function) iterations to renew the name.
//! - **Network Action Pauses:** Queries `kinetic-local::action::GLOBAL_ACTION_STATE`
//!   to deduct any paused network kyns from the age of a record. If the network was
//!   halted for an emergency upgrade, time is effectively frozen, ensuring legitimate
//!   users do not lose their names due to missed renewals.

use crate::error::KineticStoreError;
use crate::store::constants::*;
use crate::store::core::KineticRecordStore;
use kinetic_verify::signatures::VerifySignature;

impl KineticRecordStore {
    pub(crate) fn handle_put_record(
        &mut self,
        record: &kinetic_core::types::NameEnvelope,
        skip_verify: bool,
    ) -> Result<(), KineticStoreError> {
        let reveal_ref = match record {
            kinetic_core::types::NameEnvelope::Standard(r) => Some(r),
        };

        if let Some(reveal) = reveal_ref {
            let paused_kyns = if let Ok(state) = kinetic_local::action::GLOBAL_ACTION_STATE.lock() {
                state.paused_kyns_since(*reveal.kyn)
            } else {
                0
            };

            let effective_age = self
                .current_kyn
                .as_u64()
                .saturating_sub(reveal.kyn.as_u64())
                .saturating_sub(paused_kyns);

            if effective_age > kinetic_core::types::RESQUARING_EPOCH_KYNS {
                let err = KineticStoreError::VdfExpired { age: effective_age };
                err.log_warning(record.name(), "Rejecting Record:");
                return Err(err);
            }
        }

        if !skip_verify
            && let Some(reveal) = reveal_ref
            && let Err(e) = super::verification::verify_reveal(
                reveal,
                &self.storage,
                self.current_kyn,
                &self.vdf_engine,
            )
        {
            e.log_warning(record.name(), "Rejecting Reveal:");
            return Err(e);
        }

        if let Some(existing_record) = self.get_fallback(record.name()) {
            if existing_record.pubkey() != record.pubkey() {
                let physics_math = kinetic_core::physics::NetworkPhysics::default();
                let last_hb_kyn = self
                    .last_heartbeats_by_name
                    .get(record.name())
                    .copied()
                    .unwrap_or_else(|| reveal_ref.map_or(0, |r| r.kyn.as_u64()));

                let hb_age = self.current_kyn.as_u64().saturating_sub(last_hb_kyn);

                let (
                    kinetic_core::types::NameEnvelope::Standard(existing_reveal),
                    kinetic_core::types::NameEnvelope::Standard(new_reveal),
                ) = (existing_record, record);

                let base_diff = physics_math.iterations(&new_reveal.name);
                let takeover_threshold = physics_math.takeover_iterations(base_diff, hb_age);

                // Case 121: Deterministic Tie-Breaking
                if new_reveal.iterations == existing_reveal.iterations && hb_age < 100 {
                    let dist_new: Vec<u8> = new_reveal
                        .pubkey
                        .0
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
                        .0
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
                        err.log_warning(&new_reveal.name, "Rejecting Takeover Reveal:");
                        return Err(err);
                    } else {
                        tracing::info!(
                            "Valid Takeover Reveal for {}! Tie-break won!",
                            new_reveal.name
                        );
                    }
                } else if new_reveal.iterations < takeover_threshold {
                    let err = KineticStoreError::InsufficientIterations;
                    err.log_warning(&new_reveal.name, "Rejecting Takeover Reveal:");
                    return Err(err);
                } else {
                    tracing::info!(
                        "Valid Takeover Reveal for {}! Overwriting previous owner (idle for {} kyns).",
                        new_reveal.name,
                        hb_age
                    );
                }

                // Cleanup orphaned keys from previous owner
                let keys = kinetic_core::types::derive_storage_keys(
                    &new_reveal.name,
                    kinetic_core::constants::NETWORK_SALT,
                );
                for key_bytes in keys {
                    let k = libp2p::kad::RecordKey::new(&key_bytes);
                    let mut db_key = Vec::with_capacity(11 + k.as_ref().len());
                    db_key.extend_from_slice(b"kad_record:");
                    db_key.extend_from_slice(k.as_ref());
                    let _ = self.storage.delete(&db_key);
                }
                let hb_keys = kinetic_core::types::derive_heartbeat_keys(
                    &new_reveal.name,
                    kinetic_core::constants::NETWORK_SALT,
                );
                for key_bytes in hb_keys {
                    let k = libp2p::kad::RecordKey::new(&key_bytes);
                    let mut db_key = Vec::with_capacity(11 + k.as_ref().len());
                    db_key.extend_from_slice(b"kad_record:");
                    db_key.extend_from_slice(k.as_ref());
                    let _ = self.storage.delete(&db_key);
                }
            } else {
                let existing_pulse = match &existing_record {
                    kinetic_core::types::NameEnvelope::Standard(r) => r.kyn,
                };
                let new_pulse = match &record {
                    kinetic_core::types::NameEnvelope::Standard(r) => r.kyn,
                };

                if new_pulse < existing_pulse {
                    let err = KineticStoreError::StaleReveal;
                    err.log_warning(record.name(), "Rejecting Replayed Reveal:");
                    return Err(err);
                } else if record.embedded_nrs() == existing_record.embedded_nrs()
                    && record.signature() == existing_record.signature()
                {
                    return Ok(());
                } else {
                    // Updating payload of existing apex name. Verify the updated payload signature!
                    let dev_mode = kinetic_core::config::is_dev_mode();
                    if !skip_verify
                        && !dev_mode
                        && let Err(e) =
                            record.verify_signature(kinetic_core::constants::NETWORK_SALT)
                    {
                        let err = match e {
                            kinetic_verify::SignatureVerifyError::DelegatedCapabilityMissing => {
                                KineticStoreError::DelegatedCapabilityMissing
                            }
                            kinetic_verify::SignatureVerifyError::DelegatedAuthorizationInvalid => {
                                KineticStoreError::DelegatedAuthorizationInvalid
                            }
                            _ => KineticStoreError::InvalidSignature,
                        };
                        err.log_warning(
                            record.name(),
                            "Rejecting updated record due to invalid signature:",
                        );
                        return Err(err);
                    }

                    // Cryptographic Hierarchy Conflict Resolution
                    // Both records share the same pulse (kyn/granted_at), but payloads differ.
                    // We must resolve the conflict strictly by prioritization: Master Key > Delegated Key
                    let exist_auth = existing_record.authorization();
                    let new_auth = record.authorization();

                    match (exist_auth, new_auth) {
                        (Some(_), None) => {
                            // Existing is a Delegated Key, new is the Master Key.
                            // The Master Key strictly overrides the Hot Key.
                            tracing::info!(
                                name = record.name(),
                                "Master Key override detected. Prioritizing direct signature over existing delegated signature."
                            );
                        }
                        (None, Some(_)) => {
                            // Existing is the Master Key, new is a Delegated Key.
                            // The Hot Key CANNOT override a Master Key update in the same epoch.
                            let err = KineticStoreError::StaleReveal;
                            err.log_warning(
                                record.name(),
                                "Rejecting delegated update: Master Key update takes strict precedence in this epoch.",
                            );
                            return Err(err);
                        }
                        (Some(exist_manifest), Some(new_manifest)) => {
                            // Both are Delegated Keys. The one with the newer manifest (valid_from) wins.
                            if new_manifest.manifest.valid_from < exist_manifest.manifest.valid_from
                            {
                                let err = KineticStoreError::StaleReveal;
                                err.log_warning(
                                    record.name(),
                                    "Rejecting delegated update: Existing delegated manifest is newer.",
                                );
                                return Err(err);
                            }
                        }
                        (None, None) => {
                            // Both are Master Key. No strict cryptographic way to determine which was created "last"
                            // (other than network arrival time). We accept the new one (latest arrival wins).
                        }
                    }
                }
            }
        } else {
            // New record, verify signature
            let dev_mode = kinetic_core::config::is_dev_mode();
            if !skip_verify
                && !dev_mode
                && let Err(e) = record.verify_signature(kinetic_core::constants::NETWORK_SALT)
            {
                let err = match e {
                    kinetic_verify::SignatureVerifyError::DelegatedCapabilityMissing => {
                        KineticStoreError::DelegatedCapabilityMissing
                    }
                    kinetic_verify::SignatureVerifyError::DelegatedAuthorizationInvalid => {
                        KineticStoreError::DelegatedAuthorizationInvalid
                    }
                    _ => KineticStoreError::InvalidSignature,
                };
                err.log_warning(
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
            err.log_warning(name, "Rejecting Reveal:");
            return Err(err);
        }
        deque.push_back(now);

        if let Some((evicted_name, _)) = self.reveals_by_name.push(name.to_string(), record.clone())
            && evicted_name != name
        {
            self.last_heartbeats_by_name.remove(&evicted_name);
        }
        let reveal_key = [KRS_REVEAL_PREFIX, name.as_bytes()].concat();

        let mut writes_to_perform = Vec::new();

        if let Ok(bytes) = serde_json::to_vec(&record) {
            writes_to_perform.push((reveal_key, bytes));
        }

        let current_kyn = std::cmp::max(
            self.current_kyn.as_u64(),
            reveal_ref.map_or(0, |r| r.kyn.as_u64()),
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

    pub(crate) fn handle_process_heartbeat(
        &mut self,
        heartbeat: &kinetic_core::types::Heartbeat,
    ) -> Result<(), KineticStoreError> {
        // OPTIMIZATION: Check for duplicates or stale heartbeats before doing any expensive ML-DSA signature verification
        let existing_pulse = self
            .last_heartbeats_by_name
            .get(&heartbeat.name)
            .copied()
            .unwrap_or(0);

        if heartbeat.latest_kyn.0 == existing_pulse {
            // Normal duplicate via DHT gossip, ignore it silently to prevent log spam and CPU waste
            return Ok(());
        }

        if heartbeat.latest_kyn.0 < existing_pulse {
            let err = KineticStoreError::StaleHeartbeat;
            err.log_warning(&heartbeat.name, "Rejecting Heartbeat:");
            return Err(err);
        }

        let existing_record = match self.get_fallback(&heartbeat.name) {
            Some(r) => r,
            None => {
                let err = KineticStoreError::RevealNotFound;
                err.log_warning(&heartbeat.name, "Rejecting Heartbeat:");
                return Err(err);
            }
        };

        let signable = heartbeat.signable_bytes(kinetic_core::constants::NETWORK_SALT);
        let is_valid_signature = if let Some(auth) = &heartbeat.authorization {
            if existing_record
                .pubkey()
                .verify(
                    &auth.signable_bytes(kinetic_core::constants::NETWORK_SALT),
                    &auth.owner_signature,
                )
                .is_err()
            {
                let err = KineticStoreError::DelegatedAuthorizationInvalid;
                err.log_warning(&heartbeat.name, "Rejecting Heartbeat:");
                return Err(err);
            }

            let has_cap = auth
                .manifest
                .services
                .iter()
                .any(|s| s.service_type == "kinetic.capability.heartbeat");
            if !has_cap {
                let err = KineticStoreError::DelegatedCapabilityMissing;
                err.log_warning(&heartbeat.name, "Rejecting Heartbeat:");
                return Err(err);
            }

            let kid_doc = auth.kid_doc.as_ref().ok_or_else(|| {
                let err = KineticStoreError::MissingKidDocument;
                err.log_warning(&heartbeat.name, "Rejecting Heartbeat:");
                err
            })?;

            let mut verified = false;
            for ck in &kid_doc.controller_keys {
                use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as b64_url};
                if ck.key_type == "Delegated"
                    && let Ok(pubkey_bytes) = b64_url.decode(&ck.public_key)
                {
                    let temp_pubkey = kinetic_primitives::keypairs::DelegatedPubKey(pubkey_bytes);
                    let delegated_sig = kinetic_primitives::keypairs::DelegatedSignature(
                        heartbeat.owner_signature.0.clone(),
                    );
                    if temp_pubkey.verify(&signable, &delegated_sig).is_ok() {
                        verified = true;
                        break;
                    }
                }
            }
            verified
        } else {
            existing_record
                .pubkey()
                .verify(&signable, &heartbeat.owner_signature)
                .is_ok()
        };

        if !is_valid_signature {
            let err = KineticStoreError::InvalidSignature;
            err.log_warning(&heartbeat.name, "Rejecting Heartbeat:");
            return Err(err);
        }

        if heartbeat.latest_kyn.0 > self.current_kyn.as_u64() + 2 {
            let err = KineticStoreError::FutureHeartbeat;
            err.log_warning(&heartbeat.name, "Rejecting Heartbeat: future-dated:");
            return Err(err);
        }

        // Monotonicity check already performed at the top of the function.

        self.last_heartbeats_by_name
            .insert(heartbeat.name.clone(), heartbeat.latest_kyn.0);
        let hb_key = [KRS_HB_PREFIX, heartbeat.name.as_bytes()].concat();
        let hb_val = heartbeat.latest_kyn.0.to_be_bytes().to_vec();

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
