//! Cryptographic verification rules for Reveals, HostRoutingRecords, AuthorizedKids, and AuthorizedManifests.
//!
//! This module acts as the strict gatekeeper for the Kademlia DHT. It enforces
//! Ed25519 signature checks, VDF iteration verification (including loyalty discounts),
//! and timestamp freshness checks to prevent sybil attacks and namespace hijacking.

use crate::error::KineticStoreError;

/// Finding 13 (Critical): Verify a HostRoutingRecord's signature and timestamp freshness.
/// 
/// This lives in `kinetic-network` (not `kinetic-core`) because it requires the libp2p dependency
/// to extract the Ed25519 public key from the PeerId multihash.
///
/// # Arguments
///
/// * `record` - The host routing record to be verified.
///
/// # Errors
///
/// * Returns `KineticStoreError::InvalidHostRouteSignature` if the timestamp is stale (older than 10 mins) or from the future.
/// * Returns `KineticStoreError::InvalidPublicKey` if the `host_id` cannot be parsed as a valid `PeerId` containing an Ed25519 key.
/// * Returns `KineticStoreError::MalformedSignature` if the signature bytes are structurally invalid.
pub(crate) fn verify_host_routing_record(
    record: &kinetic_core::types::HostRoutingRecord,
) -> Result<(), KineticStoreError> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    // Enforce timestamp freshness — reject records older than 10 minutes,
    // and reject records more than 5 minutes in the future to prevent pinning via u64::MAX timestamps.
    let now = web_time::SystemTime::now()
        .duration_since(web_time::UNIX_EPOCH)
        .map_err(|_| KineticStoreError::InvalidHostRouteSignature)?
        .as_secs();
    if now.saturating_sub(record.timestamp) > kinetic_core::constants::TIMEOUTS_HOST_ROUTE_MAX_AGE_SECONDS {
        let err = KineticStoreError::InvalidHostRouteSignature;
        err.log_warning(
            "KIN-STORE-023",
            &record.host_id,
            &format!(
                "HostRoutingRecord is stale ({} seconds old)",
                now.saturating_sub(record.timestamp)
            ),
        );
        return Err(err);
    }
    if record.timestamp > now + 300 {
        let err = KineticStoreError::InvalidHostRouteSignature;
        err.log_warning(
            "KIN-STORE-024",
            &record.host_id,
            &format!(
                "HostRoutingRecord is from the future ({} seconds ahead)",
                record.timestamp.saturating_sub(now)
            ),
        );
        return Err(err);
    }

    // Parse the host_id as a libp2p PeerId and extract its public key.
    let host_peer_id = record
        .host_id
        .parse::<libp2p::PeerId>()
        .map_err(|_| KineticStoreError::InvalidPublicKey)?;

    // Extract the Ed25519 public key bytes from the PeerId multihash.
    // libp2p Ed25519 PeerIds encode the 32-byte public key in their multihash payload.
    // The strict identity multihash for an Ed25519 key is:
    // [0x00, 0x24, 0x08, 0x01, 0x12, 0x20] followed by 32 bytes of public key.
    let pubkey_bytes: [u8; 32] = match host_peer_id.as_ref().digest() {
        bytes if bytes.len() == 38 && bytes[0..6] == [0x00, 0x24, 0x08, 0x01, 0x12, 0x20] => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes[6..38]);
            arr
        }
        _ => return Err(KineticStoreError::InvalidPublicKey),
    };

    let verifying_key =
        VerifyingKey::from_bytes(&pubkey_bytes).map_err(|_| KineticStoreError::InvalidPublicKey)?;

    let sig = Signature::from_slice(&record.signature)
        .map_err(|_| KineticStoreError::MalformedSignature)?;

    let signable = record.signable_bytes();
    verifying_key
        .verify(&signable, &sig)
        .map_err(|_| KineticStoreError::InvalidHostRouteSignature)
}

#[inline]
fn get_u64_from_sled(
    storage: &std::sync::Arc<dyn kinetic_core::traits::StorageEngine>,
    key: &[u8],
) -> Option<u64> {
    match storage.get(key) {
        Ok(Some(bytes)) if bytes.len() == 8 => Some(u64::from_be_bytes(
            bytes[..8].try_into().unwrap_or([0u8; 8]),
        )),
        _ => None,
    }
}

/// Computes the required VDF iterations for a reveal, considering potential loyalty discounts.
///
/// # Arguments
///
/// * `reveal` - The proposed reveal to compute iterations for.
/// * `current_drand_round` - The current global drand pulse round.
/// * `engine` - The VDF engine reference used to verify any `previous_proof` attached for a discount.
///
/// # Errors
///
/// * Returns `KineticStoreError::InvalidName` if the apex name is malformed.
/// * Returns `KineticStoreError::InvalidDrandHex` if the Drand randomness is not valid hex.
pub(crate) fn compute_required_iterations(
    reveal: &kinetic_core::types::Reveal,
    current_drand_round: u64,
    engine: &dyn kinetic_core::traits::VdfEngine,
) -> Result<u64, KineticStoreError> {
    if let Err(e) = kinetic_core::types::names::is_valid_apex_name(&reveal.name) {
        let err = KineticStoreError::InvalidName;
        err.log_warning(
            "KIN-STORE-029",
            &reveal.name,
            &format!("Rejecting Kademlia Reveal: Invalid name: {:?}", e),
        );
        return Err(err);
    }

    use kinetic_core::types::Commitment;
    use sha2::{Digest, Sha256};

    let consensus_math = kinetic_core::consensus_math::ConsensusParams::default();

    let drand_rand = hex::decode(&reveal.drand_randomness).map_err(|_| {
        let err = KineticStoreError::InvalidDrandHex;
        err.log_warning(
            "KIN-STORE-028",
            &reveal.name,
            "Rejecting Kademlia Reveal: Invalid Drand hex",
        );
        err
    })?;

    let base_required_iterations =
        consensus_math.required_iterations(&reveal.name, &drand_rand);
    let required_iterations = if let Some(prev) = &reveal.previous_proof {
        // Verify previous proof
        let mut prev_hasher = Sha256::new();
        prev_hasher.update(reveal.name.as_bytes());
        prev_hasher.update(prev.salt);
        let prev_drand_rand = hex::decode(&prev.drand_randomness).map_err(|_| {
            let err = KineticStoreError::InvalidDrandHex;
            err.log_warning(
                "KIN-STORE-028",
                &reveal.name,
                "Rejecting Kademlia Reveal: Previous record has invalid Drand hex",
            );
            err
        })?;
        prev_hasher.update(&prev_drand_rand);
        prev_hasher.update(&reveal.pubkey);
        let mut prev_hash = [0u8; 32];
        prev_hash.copy_from_slice(&prev_hasher.finalize());
        let prev_challenge = Commitment { hash: prev_hash };

        let prev_valid = matches!(
            engine.verify(&prev_challenge, &prev.vdf_proof, prev.iterations),
            Ok(true)
        );

        let prev_req =
            consensus_math.required_iterations(&reveal.name, &prev_drand_rand);
        let is_not_too_old = current_drand_round.saturating_sub(prev.drand_pulse)
            <= kinetic_core::types::RESQUARING_EPOCH_ROUNDS * 2;

        if prev_valid && prev.iterations >= prev_req && is_not_too_old {
            let normalized_name = kinetic_core::types::normalize_name(&reveal.name);
            let name_len = normalized_name
                .strip_suffix(kinetic_core::constants::TLD_SUFFIX)
                .unwrap_or(&normalized_name)
                .len();
            let discount_iterations = match name_len {
                1 => kinetic_core::constants::CONSENSUS_VDF_DISCOUNT_MIN_ITERATIONS,                                  // 100% discount (minimum iterations)
                63 => base_required_iterations,             // 0% discount (forces lottery re-roll)
                2..=6 => base_required_iterations / 2,      // 50% discount
                7..=10 => base_required_iterations / 5,     // 80% discount
                _ => (base_required_iterations * kinetic_core::constants::CONSENSUS_VDF_DISCOUNT_PERCENTAGE) / 100, // 85% discount for 11+
            };

            tracing::info!(
                "Valid PreviousProof attached for {}. Granting loyalty discount for length {}.",
                reveal.name,
                name_len
            );
            std::cmp::max(kinetic_core::constants::CONSENSUS_VDF_DISCOUNT_MIN_ITERATIONS, discount_iterations)
        } else {
            tracing::warn!(
                "Invalid PreviousProof attached for {}. Falling back to full difficulty.",
                reveal.name
            );
            base_required_iterations
        }
    } else {
        base_required_iterations
    };
    Ok(required_iterations)
}

/// Verifies a Reveal commitment payload completely.
///
/// This checks the Ed25519 signature, ensures a prior `Commitment` exists in the local DHT shard
/// (unless in dev mode), enforces the required VDF iteration threshold, and verifies the VDF proof itself.
///
/// # Arguments
///
/// * `reveal` - The Reveal payload.
/// * `storage` - The local sled storage engine (to look up the commitment).
/// * `current_drand_round` - The current drand pulse round.
/// * `engine` - The VDF engine used to verify the proof.
///
/// # Errors
///
/// * Returns `KineticStoreError::InvalidName` if the name is invalid.
/// * Returns `KineticStoreError::InvalidPublicKey` or `KineticStoreError::InvalidSignature` if Ed25519 checks fail.
/// * Returns `KineticStoreError::StaleReveal` if the commitment is too recent (age < 10 rounds).
/// * Returns `KineticStoreError::MissingCommitment` if no prior commitment is found in the DHT.
/// * Returns `KineticStoreError::InsufficientIterations` if the iterations do not meet the consensus threshold.
/// * Returns `KineticStoreError::InvalidVdf` if the VDF proof fails verification.
pub(crate) fn verify_reveal(
    reveal: &kinetic_core::types::Reveal,
    storage: &std::sync::Arc<dyn kinetic_core::traits::StorageEngine>,
    current_drand_round: u64,
    engine: &std::sync::Arc<dyn kinetic_core::traits::VdfEngine>,
) -> Result<(), KineticStoreError> {
    if let Err(e) = reveal.validate() {
        let err = KineticStoreError::InvalidName;
        err.log_warning(
            "KIN-STORE-029",
            &reveal.name,
            &format!("Rejecting Kademlia Reveal: Validation failed: {:?}", e),
        );
        return Err(err);
    }

    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    use kinetic_core::types::Commitment;
    use sha2::{Digest, Sha256};

    let signable = reveal.signable_bytes();
    let pubkey = match VerifyingKey::try_from(reveal.pubkey.as_slice()) {
        Ok(k) => k,
        Err(_) => {
            let err = KineticStoreError::InvalidPublicKey;
            err.log_warning(
                "KIN-STORE-024",
                &reveal.name,
                "Rejecting Kademlia Reveal: Invalid Ed25519 PublicKey",
            );
            return Err(err);
        }
    };
    let signature = match Signature::from_slice(&reveal.signature) {
        Ok(s) => s,
        Err(_) => {
            let err = KineticStoreError::MalformedSignature;
            err.log_warning(
                "KIN-STORE-025",
                &reveal.name,
                "Rejecting Kademlia Reveal: Malformed Ed25519 Signature",
            );
            return Err(err);
        }
    };

    if pubkey.verify(&signable, &signature).is_err() {
        let err = KineticStoreError::InvalidSignature;
        err.log_warning(
            "KIN-STORE-026",
            &reveal.name,
            "Rejecting Kademlia Reveal: Invalid Ed25519 Signature",
        );
        return Err(err);
    }

    let drand_rand = hex::decode(&reveal.drand_randomness).map_err(|_| {
        let err = KineticStoreError::InvalidDrandHex;
        err.log_warning(
            "KIN-STORE-028",
            &reveal.name,
            "Rejecting Kademlia Reveal: Invalid Drand Randomness Hex",
        );
        err
    })?;
    let mut hasher = Sha256::new();
    hasher.update(reveal.name.as_bytes());
    hasher.update(reveal.salt);
    hasher.update(&drand_rand);
    hasher.update(&reveal.pubkey);
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&hasher.finalize());
    let challenge = Commitment { hash };

    let dev_mode = kinetic_core::config::is_dev_mode();

    let mut commit_key = Vec::with_capacity(crate::store::constants::KRS_COMMIT_PREFIX.len() + 32);
    commit_key.extend_from_slice(crate::store::constants::KRS_COMMIT_PREFIX);
    commit_key.extend_from_slice(&hash);

    let commit_round = get_u64_from_sled(storage, &commit_key);

    if let Some(commit_round) = commit_round {
        if !dev_mode && current_drand_round.saturating_sub(commit_round) < 10 {
            let err = KineticStoreError::StaleReveal;
            err.log_warning(
                "KIN-STORE-027",
                &reveal.name,
                "Rejecting Reveal: Commitment is too recent (age < 10 rounds)",
            );
            return Err(err);
        }
        tracing::info!(
            "Commitment matched for Reveal of {} (committed around round {})",
            reveal.name,
            commit_round
        );
    } else if !dev_mode {
        let err = KineticStoreError::MissingCommitment;
        err.log_warning(
            "KIN-STORE-028",
            &reveal.name,
            "Rejecting Reveal: No prior Commitment found in DHT!",
        );
        return Err(err);
    } else {
        tracing::info!(
            "Dev mode: Bypassing commitment presence check for {}",
            reveal.name
        );
    }

    let required_iterations =
        compute_required_iterations(reveal, current_drand_round, engine.as_ref())?;

    if dev_mode {
        tracing::info!(
            "Dev mode: Bypassing VDF proof verification for {}",
            reveal.name
        );
        return Ok(());
    }

    if reveal.iterations < required_iterations {
        let err = KineticStoreError::InsufficientIterations;
        err.log_warning(
            "KIN-STORE-030",
            &reveal.name,
            &format!(
                "Rejecting Reveal: Insufficient VDF iterations. Provided {}, Required {}",
                reveal.iterations, required_iterations
            ),
        );
        return Err(err);
    }

    match engine.verify(&challenge, &reveal.vdf_proof, reveal.iterations) {
        Ok(true) => Ok(()),
        Ok(false) => {
            let err = KineticStoreError::InvalidVdf;
            err.log_warning(
                "KIN-STORE-031",
                &reveal.name,
                "Rejecting Kademlia Reveal: Invalid VDF Proof",
            );
            Err(err)
        }
        Err(e) => {
            let err = KineticStoreError::VdfEngineError(e.to_string());
            err.log_warning(
                "KIN-STORE-031",
                &reveal.name,
                "Rejecting Kademlia Reveal: VDF Engine Failure",
            );
            Err(err)
        }
    }
}

/// Verifies an `AuthorizedKid` payload by checking the domain owner's signature.
///
/// # Arguments
///
/// * `auth_kid` - The AuthorizedKid payload to verify.
/// * `active_reveal` - The currently active `Reveal` for this domain, which provides the public key.
///
/// # Errors
///
/// Returns `KineticStoreError::InvalidKidSignature` if the reveal is missing, the signature is invalid,
/// or the inner KID document fails self-verification.
pub(crate) fn verify_authorized_kid(
    auth_kid: &kinetic_core::types::AuthorizedKid,
    active_reveal: Option<&kinetic_core::types::Reveal>,
) -> Result<(), KineticStoreError> {
    let reveal = active_reveal.ok_or_else(|| {
        let err = KineticStoreError::InvalidKidSignature;
        err.log_warning(
            "KIN-STORE-032",
            &auth_kid.name,
            "Rejecting AuthorizedKid: No active reveal found",
        );
        err
    })?;

    let pubkey = ed25519_dalek::VerifyingKey::try_from(reveal.pubkey.as_slice())
        .map_err(|_| KineticStoreError::InvalidKidSignature)?;

    use ed25519_dalek::Verifier;
    let sig = ed25519_dalek::Signature::from_slice(&auth_kid.owner_signature)
        .map_err(|_| KineticStoreError::InvalidKidSignature)?;

    if pubkey.verify(&auth_kid.signable_bytes(), &sig).is_ok() && auth_kid.kid_doc.verify().is_ok()
    {
        tracing::info!(
            "KineticRecordStore::put accepted AuthorizedKid for {}",
            auth_kid.kid_doc.kid.as_str()
        );
        Ok(())
    } else {
        let err = KineticStoreError::InvalidKidSignature;
        err.log_warning(
            "KIN-STORE-017",
            &auth_kid.name,
            "Rejecting AuthorizedKid: invalid signature or invalid document",
        );
        Err(err)
    }
}

/// Verifies an `AuthorizedManifest` payload.
///
/// Ensures that the manifest is signed by the domain owner and prevents rollback attacks
/// by ensuring the manifest version is strictly greater than any existing version.
///
/// # Arguments
///
/// * `auth_manifest` - The AuthorizedManifest payload to verify.
/// * `active_reveal` - The currently active `Reveal` for this domain.
/// * `existing_record` - The pre-existing DHT record for this manifest, if any, used for version anti-rollback.
///
/// # Errors
///
/// Returns `KineticStoreError::InvalidManifestSignature` if the reveal is missing, the owner signature is invalid,
/// the KID document is missing/invalid, or a version rollback is detected.
pub(crate) fn verify_authorized_manifest(
    auth_manifest: &kinetic_core::types::AuthorizedManifest,
    active_reveal: Option<&kinetic_core::types::Reveal>,
    existing_record: Option<&std::borrow::Cow<'_, libp2p::kad::Record>>,
) -> Result<(), KineticStoreError> {
    let reveal = active_reveal.ok_or_else(|| {
        let err = KineticStoreError::InvalidManifestSignature;
        err.log_warning(
            "KIN-STORE-033",
            &auth_manifest.name,
            "Rejecting AuthorizedManifest: No active reveal found",
        );
        err
    })?;

    let pubkey = ed25519_dalek::VerifyingKey::try_from(reveal.pubkey.as_slice())
        .map_err(|_| KineticStoreError::InvalidManifestSignature)?;

    use ed25519_dalek::Verifier;
    let sig = ed25519_dalek::Signature::from_slice(&auth_manifest.owner_signature)
        .map_err(|_| KineticStoreError::InvalidManifestSignature)?;

    if pubkey
        .verify(&auth_manifest.signable_bytes(), &sig)
        .is_err()
    {
        let err = KineticStoreError::InvalidManifestSignature;
        err.log_warning(
            "KIN-STORE-018",
            &auth_manifest.name,
            "Rejecting AuthorizedManifest: invalid owner signature",
        );
        return Err(err);
    }

    let kid_doc = auth_manifest
        .kid_doc
        .as_ref()
        .ok_or(KineticStoreError::InvalidManifestSignature)?;
    kid_doc
        .verify()
        .map_err(|_| KineticStoreError::InvalidManifestSignature)?;
    auth_manifest
        .manifest
        .verify(kid_doc)
        .map_err(|_| KineticStoreError::InvalidManifestSignature)?;

    if let Some(existing) = existing_record {
        if let Ok(old_manifest) =
            serde_json::from_slice::<kinetic_core::types::AuthorizedManifest>(&existing.value)
        {
            if auth_manifest.manifest.version <= old_manifest.manifest.version {
                let err = KineticStoreError::InvalidManifestSignature;
                err.log_warning(
                    "KIN-STORE-034",
                    &auth_manifest.name,
                    "Rejecting AuthorizedManifest: Version rollback detected",
                );
                return Err(err);
            }
        }
    }

    tracing::info!(
        "KineticRecordStore::put accepted AuthorizedManifest for {}",
        auth_manifest.manifest.kid.as_str()
    );
    Ok(())
}
