use crate::error::KineticStoreError;
use crate::store::constants::*;
use crate::store::core::KineticRecordStore;
use kinetic_core::traits::StorageEngine;
use libp2p::kad;

impl KineticRecordStore {
    pub(crate) fn handle_reveal(
        &mut self,
        reveal: &kinetic_core::types::Reveal,
    ) -> Result<(), kad::store::Error> {
        // Finding 3: Use the shared constant instead of a hardcoded magic number.
        if self.current_drand_round.saturating_sub(reveal.drand_pulse)
            > kinetic_core::types::RESQUARING_EPOCH_ROUNDS
        {
            let age = self.current_drand_round.saturating_sub(reveal.drand_pulse);
            let err = KineticStoreError::VdfExpired { age };
            tracing::warn!(
                error_code = "KIN-STORE-001",
                name = %reveal.name,
                age = age,
                severity = ?err.severity(),
                "Rejecting Reveal: {}", err
            );
            return Err(err.into());
        }

        if !self.verify_reveal_internal(reveal) {
            let err = KineticStoreError::InvalidVdf;
            tracing::warn!(
                error_code = "KIN-STORE-002",
                name = %reveal.name,
                severity = ?err.severity(),
                "Rejecting Reveal: {}", err
            );
            return Err(err.into());
        }

        if let Some(existing_reveal) = self.reveals_by_name.get(&reveal.name) {
            if existing_reveal.pubkey != reveal.pubkey {
                let consensus_math = kinetic_core::consensus_math::ConsensusParams::default();
                let last_hb_round = self
                    .last_heartbeats_by_name
                    .get(&reveal.name)
                    .copied()
                    .unwrap_or(reveal.drand_pulse);

                if let Some(&(hib_round, hib_iters)) = self.hibernations_by_name.get(&reveal.name) {
                    let hib_age = self.current_drand_round.saturating_sub(hib_round);
                    let exemption_rounds = consensus_math.hibernation_exemption_rounds(hib_iters);
                    if hib_age < exemption_rounds {
                        let err = KineticStoreError::Hibernating;
                        tracing::warn!(
                            error_code = "KIN-STORE-003",
                            name = %reveal.name,
                            hib_age = hib_age,
                            exemption_rounds = exemption_rounds,
                            severity = ?err.severity(),
                            "Rejecting Steal Reveal: {}", err
                        );
                        return Err(err.into());
                    }
                }

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
                        tracing::warn!(
                            error_code = "KIN-STORE-004",
                            name = %reveal.name,
                            severity = ?err.severity(),
                            "Rejecting Steal Reveal: {}", err
                        );
                        return Err(err.into());
                    } else {
                        tracing::info!("Valid Steal Reveal for {}! Tie-break won!", reveal.name);
                    }
                } else if reveal.iterations < steal_threshold {
                    let err = KineticStoreError::InsufficientIterations;
                    tracing::warn!(
                        error_code = "KIN-STORE-005",
                        name = %reveal.name,
                        iterations = reveal.iterations,
                        required = steal_threshold,
                        hb_age = hb_age,
                        severity = ?err.severity(),
                        "Rejecting Steal Reveal: {}", err
                    );
                    return Err(err.into());
                } else {
                    tracing::info!("Valid Steal Reveal for {}! Overwriting previous owner (idle for {} rounds).", reveal.name, hb_age);
                }
            }
        }

        self.reveals_by_name
            .put(reveal.name.clone(), reveal.clone());
        let reveal_key = format!("{}{}", KRS_REVEAL_PREFIX, reveal.name);
        if let Ok(bytes) = serde_json::to_vec(&reveal) {
            let _ = self.storage.put(reveal_key.as_bytes(), &bytes);
        }

        if let Some(spent) = reveal.points_spent {
            if spent > 0 {
                let mut balance = self
                    .points_by_pubkey
                    .get(&reveal.pubkey)
                    .copied()
                    .unwrap_or(0);
                balance = balance.saturating_sub(spent);
                self.points_by_pubkey.insert(reveal.pubkey.clone(), balance);
                let key = format!("{}{}", KRS_POINTS_PREFIX, hex::encode(&reveal.pubkey));
                let _ = self.storage.put(key.as_bytes(), &balance.to_be_bytes());
                tracing::info!(
                    "Deducted {} points from {}. New balance: {}",
                    spent,
                    hex::encode(&reveal.pubkey),
                    balance
                );
            }
        }

        if let Some(miner_pk) = &reveal.miner_pubkey {
            let mut balance = self.points_by_pubkey.get(miner_pk).copied().unwrap_or(0);
            balance = balance.saturating_add(reveal.iterations);
            self.points_by_pubkey.insert(miner_pk.clone(), balance);
            let key = format!("{}{}", KRS_POINTS_PREFIX, hex::encode(miner_pk));
            let _ = self.storage.put(key.as_bytes(), &balance.to_be_bytes());
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
        if self.accepted_reveals_timestamps.len() > 100 {
            tracing::warn!("ALERT: High registration rate ({} valid reveals accepted in the last hour). VDF difficulty parameters may need revision.", self.accepted_reveals_timestamps.len());
        }

        let current_round = std::cmp::max(self.current_drand_round, reveal.drand_pulse);
        self.last_heartbeats_by_name
            .insert(reveal.name.clone(), current_round);
        let hb_key = format!("{}{}", KRS_HB_PREFIX, reveal.name);
        let _ = self
            .storage
            .put(hb_key.as_bytes(), &current_round.to_be_bytes());

        Ok(())
    }

    pub(crate) fn handle_hibernation(
        &mut self,
        hibernation: &kinetic_core::types::Hibernation,
    ) -> Result<(), kad::store::Error> {
        let existing_reveal = match self.reveals_by_name.get(&hibernation.name) {
            Some(r) => r,
            None => {
                let err = KineticStoreError::RevealNotFound;
                tracing::warn!(
                    error_code = "KIN-STORE-006",
                    name = %hibernation.name,
                    severity = ?err.severity(),
                    "Rejecting Hibernation: {}", err
                );
                return Err(err.into());
            }
        };

        let signable = hibernation.signable_bytes();
        let pubkey = ed25519_dalek::VerifyingKey::try_from(existing_reveal.pubkey.as_slice())
            .map_err(|_| {
                let err = KineticStoreError::InvalidPublicKey;
                tracing::warn!(
                    error_code = "KIN-STORE-007",
                    name = %hibernation.name,
                    severity = ?err.severity(),
                    "Rejecting Hibernation: {}", err
                );
                kad::store::Error::ValueTooLarge
            })?;
        let sig = ed25519_dalek::Signature::from_slice(&hibernation.signature).map_err(|_| {
            let err = KineticStoreError::MalformedSignature;
            tracing::warn!(
                error_code = "KIN-STORE-008",
                name = %hibernation.name,
                severity = ?err.severity(),
                "Rejecting Hibernation: {}", err
            );
            kad::store::Error::ValueTooLarge
        })?;

        use ed25519_dalek::Verifier;
        if pubkey.verify(&signable, &sig).is_err() {
            let err = KineticStoreError::InvalidSignature;
            tracing::warn!(
                error_code = "KIN-STORE-009",
                name = %hibernation.name,
                severity = ?err.severity(),
                "Rejecting Hibernation: {}", err
            );
            return Err(err.into());
        }

        use kinetic_core::traits::VdfEngine;
        use kinetic_vdf::ChiaVdfEngine;
        use sha2::{Digest as _, Sha256};

        let challenge_bytes =
            hex::decode(&hibernation.drand_randomness).unwrap_or_else(|_| vec![0u8; 32]);
        let mut hasher = Sha256::new();
        hasher.update(hibernation.name.as_bytes());
        hasher.update(hibernation.salt);
        hasher.update(&challenge_bytes);
        hasher.update(&existing_reveal.pubkey);
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&hasher.finalize());
        let challenge = kinetic_core::types::Commitment { hash };

        let engine = ChiaVdfEngine::new();
        match engine.verify(&challenge, &hibernation.vdf_proof, hibernation.iterations) {
            Ok(true) => {
                let consensus_math = kinetic_core::consensus_math::ConsensusParams::default();
                let exemption_rounds =
                    consensus_math.hibernation_exemption_rounds(hibernation.iterations);
                tracing::info!(
                    "Accepted valid Hibernation VDF for {}. Exempt from heartbeats for {} rounds.",
                    hibernation.name,
                    exemption_rounds
                );

                let current_round = self.current_drand_round;
                self.hibernations_by_name.insert(
                    hibernation.name.clone(),
                    (current_round, hibernation.iterations),
                );
                let hib_key = format!("{}{}", KRS_HIB_PREFIX, hibernation.name);
                let mut val = Vec::new();
                val.extend_from_slice(&current_round.to_be_bytes());
                val.extend_from_slice(&hibernation.iterations.to_be_bytes());
                let _ = self.storage.put(hib_key.as_bytes(), &val);
                Ok(())
            }
            Ok(false) => {
                let err = KineticStoreError::InvalidVdf;
                tracing::warn!(
                    error_code = "KIN-STORE-010",
                    name = %hibernation.name,
                    iterations = hibernation.iterations,
                    severity = ?err.severity(),
                    "Hibernation rejected: {}", err
                );
                Err(err.into())
            }
            Err(e) => {
                let err = KineticStoreError::VdfEngineError(e.to_string());
                tracing::warn!(
                    error_code = "KIN-STORE-011",
                    name = %hibernation.name,
                    severity = ?err.severity(),
                    "Hibernation rejected: {}", err
                );
                Err(err.into())
            }
        }
    }

    pub(crate) fn handle_heartbeat(
        &mut self,
        heartbeat: &kinetic_core::types::Heartbeat,
    ) -> Result<(), kad::store::Error> {
        let existing_reveal = match self.reveals_by_name.get(&heartbeat.name) {
            Some(r) => r,
            None => {
                let err = KineticStoreError::RevealNotFound;
                tracing::warn!(
                    error_code = "KIN-STORE-012",
                    name = %heartbeat.name,
                    severity = ?err.severity(),
                    "Rejecting Heartbeat: {}", err
                );
                return Err(err.into());
            }
        };

        let signable = heartbeat.signable_bytes();
        let pubkey = ed25519_dalek::VerifyingKey::try_from(existing_reveal.pubkey.as_slice())
            .map_err(|_| {
                let err = KineticStoreError::InvalidPublicKey;
                tracing::warn!(
                    error_code = "KIN-STORE-013",
                    name = %heartbeat.name,
                    severity = ?err.severity(),
                    "Rejecting Heartbeat: {}", err
                );
                kad::store::Error::ValueTooLarge
            })?;
        let sig = ed25519_dalek::Signature::from_slice(&heartbeat.signature).map_err(|_| {
            let err = KineticStoreError::MalformedSignature;
            tracing::warn!(
                error_code = "KIN-STORE-014",
                name = %heartbeat.name,
                severity = ?err.severity(),
                "Rejecting Heartbeat: {}", err
            );
            kad::store::Error::ValueTooLarge
        })?;

        use ed25519_dalek::Verifier;
        if pubkey.verify(&signable, &sig).is_err() {
            let err = KineticStoreError::InvalidSignature;
            tracing::warn!(
                error_code = "KIN-STORE-015",
                name = %heartbeat.name,
                severity = ?err.severity(),
                "Rejecting Heartbeat: {}", err
            );
            return Err(err.into());
        }

        if heartbeat.latest_drand_pulse > self.current_drand_round + 2 {
            let err = KineticStoreError::StaleHeartbeat;
            tracing::warn!(
                error_code = "KIN-STORE-021",
                name = %heartbeat.name,
                received_pulse = heartbeat.latest_drand_pulse,
                current_pulse = self.current_drand_round,
                severity = ?err.severity(),
                "Rejecting Heartbeat: future-dated"
            );
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
            tracing::warn!(
                error_code = "KIN-STORE-020",
                name = %heartbeat.name,
                received_pulse = heartbeat.latest_drand_pulse,
                existing_pulse = existing_pulse,
                severity = ?err.severity(),
                "Rejecting Heartbeat: {}", err
            );
            return Err(err.into());
        }

        self.last_heartbeats_by_name
            .insert(heartbeat.name.clone(), heartbeat.latest_drand_pulse);
        let hb_key = format!("{}{}", KRS_HB_PREFIX, heartbeat.name);
        let _ = self.storage.put(
            hb_key.as_bytes(),
            &heartbeat.latest_drand_pulse.to_be_bytes(),
        );
        Ok(())
    }
}
