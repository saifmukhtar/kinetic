use crate::error::KineticStoreError;

/// Finding 13 (Critical): Verify a HostRoutingRecord's signature and timestamp freshness.
/// This lives in kinetic-network (not kinetic-core) because it requires the libp2p dependency
/// to extract the Ed25519 public key from the PeerId multihash.
pub(crate) fn verify_host_routing_record(
    record: &kinetic_core::types::HostRoutingRecord,
) -> Result<(), KineticStoreError> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    // Enforce timestamp freshness — reject records older than 10 minutes.
    let now = web_time::SystemTime::now()
        .duration_since(web_time::UNIX_EPOCH)
        .map_err(|_| KineticStoreError::InvalidHostRouteSignature)?
        .as_secs();
    if now.saturating_sub(record.timestamp) > kinetic_core::config::HOST_ROUTE_MAX_AGE_SECS {
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

    // Parse the host_id as a libp2p PeerId and extract its public key.
    let host_peer_id = record
        .host_id
        .parse::<libp2p::PeerId>()
        .map_err(|_| KineticStoreError::InvalidPublicKey)?;

    // Extract the Ed25519 public key bytes from the PeerId multihash.
    // libp2p Ed25519 PeerIds encode the 32-byte public key in their multihash payload.
    let pubkey_bytes: [u8; 32] = match host_peer_id.as_ref().digest() {
        bytes if bytes.len() >= 36 => {
            // Multihash format: <varint code> <varint length> <payload>
            // For identity multihash, the payload starts at byte 2 and contains
            // the protobuf-encoded public key. The last 32 bytes are the raw ed25519 key.
            let payload = &bytes[bytes.len() - 32..];
            let mut arr = [0u8; 32];
            arr.copy_from_slice(payload);
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

pub(crate) fn verify_reveal(
    reveal: &kinetic_core::types::Reveal,
    storage: &std::sync::Arc<dyn kinetic_core::traits::StorageEngine>,
    current_drand_round: u64,
    engine: &std::sync::Arc<dyn kinetic_core::traits::VdfEngine>,
) -> Result<(), KineticStoreError> {
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

    let consensus_math = kinetic_core::consensus_math::ConsensusParams::default();
    let base_required_iterations =
        consensus_math.required_iterations(&reveal.name, reveal.drand_pulse);

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
        prev_hasher.update(prev_drand_rand);
        prev_hasher.update(&reveal.pubkey);
        let mut prev_hash = [0u8; 32];
        prev_hash.copy_from_slice(&prev_hasher.finalize());
        let prev_challenge = Commitment { hash: prev_hash };

        let prev_valid = matches!(
            engine.verify(&prev_challenge, &prev.vdf_proof, prev.iterations),
            Ok(true)
        );

        let prev_req = consensus_math.required_iterations(&reveal.name, prev.drand_pulse);
        let is_not_too_old = current_drand_round.saturating_sub(prev.drand_pulse)
            <= kinetic_core::types::RESQUARING_EPOCH_ROUNDS * 2;

        if prev_valid && prev.iterations >= prev_req && is_not_too_old {
            let normalized_name = kinetic_core::types::normalize_name(&reveal.name);
            let name_len = normalized_name
                .strip_suffix(kinetic_core::constants::TLD_SUFFIX)
                .unwrap_or(&normalized_name)
                .len();
            let discount_iterations = match name_len {
                1 => 1000,                                  // 100% discount (minimum 1000 iterations)
                63 => base_required_iterations,             // 0% discount (forces lottery re-roll)
                2..=6 => base_required_iterations / 2,      // 50% discount
                7..=10 => base_required_iterations / 5,     // 80% discount
                _ => (base_required_iterations * 15) / 100, // 85% discount for 11+
            };

            tracing::info!(
                "Valid PreviousProof attached for {}. Granting loyalty discount for length {}.",
                reveal.name,
                name_len
            );
            std::cmp::max(1000, discount_iterations)
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

pub(crate) fn verify_authorized_manifest(
    auth_manifest: &kinetic_core::types::AuthorizedManifest,
    active_reveal: Option<&kinetic_core::types::Reveal>,
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

    if pubkey.verify(&auth_manifest.signable_bytes(), &sig).is_ok() {
        tracing::info!(
            "KineticRecordStore::put accepted AuthorizedManifest for {}",
            auth_manifest.manifest.kid.as_str()
        );
        Ok(())
    } else {
        let err = KineticStoreError::InvalidManifestSignature;
        err.log_warning(
            "KIN-STORE-018",
            &auth_manifest.name,
            "Rejecting AuthorizedManifest: invalid signature",
        );
        Err(err)
    }
}
