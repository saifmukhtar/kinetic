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
    if now.saturating_sub(record.timestamp) > 600 {
        tracing::warn!(
            "HostRoutingRecord for {} is stale ({} seconds old)",
            record.host_id,
            now.saturating_sub(record.timestamp)
        );
        return Err(KineticStoreError::InvalidHostRouteSignature);
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

pub(crate) fn verify_reveal(
    reveal: &kinetic_core::types::Reveal,
    commitments_by_hash: &std::collections::HashMap<[u8; 32], u64>,
    points_by_pubkey: &std::collections::HashMap<Vec<u8>, u64>,
    current_drand_round: u64,
) -> bool {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    use kinetic_core::traits::VdfEngine;
    use kinetic_core::types::Commitment;
    use kinetic_vdf::ChiaVdfEngine;
    use sha2::{Digest, Sha256};

    let signable = reveal.signable_bytes();
    let pubkey = match VerifyingKey::try_from(reveal.pubkey.as_slice()) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let signature = match Signature::from_slice(&reveal.signature) {
        Ok(s) => s,
        Err(_) => return false,
    };

    if pubkey.verify(&signable, &signature).is_err() {
        tracing::warn!("Rejecting Kademlia Reveal: Invalid Ed25519 Signature");
        return false;
    }

    let engine = ChiaVdfEngine::new();
    let challenge_bytes =
        hex::decode(&reveal.drand_randomness).unwrap_or_else(|_| vec![0u8; 32]);
    let mut hasher = Sha256::new();
    hasher.update(reveal.name.as_bytes());
    hasher.update(reveal.salt);
    hasher.update(&challenge_bytes);
    hasher.update(&reveal.pubkey);
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&hasher.finalize());
    let challenge = Commitment { hash };

    let dev_mode = kinetic_core::config::is_dev_mode();

    if let Some(&commit_round) = commitments_by_hash.get(&hash) {
        if !dev_mode && current_drand_round.saturating_sub(commit_round) < 10 {
            tracing::warn!(
                "Rejecting Reveal for {}: Commitment is too recent (age < 10 rounds)",
                reveal.name
            );
            return false;
        }
        tracing::info!(
            "Commitment matched for Reveal of {} (committed around round {})",
            reveal.name,
            commit_round
        );
    } else if !dev_mode {
        tracing::warn!(
            "Rejecting Reveal for {}: No prior Commitment found in DHT!",
            reveal.name
        );
        return false;
    } else {
        tracing::info!(
            "Dev mode: Bypassing commitment presence check for {}",
            reveal.name
        );
    }

    let consensus_math = kinetic_core::consensus_math::ConsensusParams::default();
    let base_required_iterations =
        consensus_math.required_iterations(&reveal.name, reveal.drand_pulse);

    let mut required_iterations = if let Some(prev) = &reveal.previous_proof {
        // Verify previous proof
        let mut prev_hasher = Sha256::new();
        prev_hasher.update(reveal.name.as_bytes());
        prev_hasher.update(prev.salt);
        prev_hasher
            .update(hex::decode(&prev.drand_randomness).unwrap_or_else(|_| vec![0u8; 32]));
        prev_hasher.update(&reveal.pubkey);
        let mut prev_hash = [0u8; 32];
        prev_hash.copy_from_slice(&prev_hasher.finalize());
        let prev_challenge = Commitment { hash: prev_hash };

        let prev_valid = matches!(
            engine.verify(&prev_challenge, &prev.vdf_proof, prev.iterations),
            Ok(true)
        );

        let prev_req =
            consensus_math.required_iterations(&reveal.name, prev.drand_pulse);
        let is_not_too_old = current_drand_round.saturating_sub(prev.drand_pulse)
            <= kinetic_core::types::RESQUARING_EPOCH_ROUNDS * 2;

        if prev_valid && prev.iterations >= prev_req && is_not_too_old {
            tracing::info!(
                "Valid PreviousProof attached for {}. Granting 80% VDF iteration discount.",
                reveal.name
            );
            std::cmp::max(1, base_required_iterations / 5)
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

    if let Some(spent) = reveal.points_spent {
        if spent > 0 {
            let balance = points_by_pubkey
                .get(&reveal.pubkey)
                .copied()
                .unwrap_or(0);
            if balance < spent {
                tracing::warn!(
                    "Rejecting Reveal for {}: Insufficient points (spent {}, balance {})",
                    reveal.name,
                    spent,
                    balance
                );
                return false;
            }
            required_iterations = required_iterations.saturating_sub(spent);
            tracing::info!(
                "Reveal for {} spent {} points. Reduced required iterations to {}.",
                reveal.name,
                spent,
                required_iterations
            );
        }
    }

    if dev_mode {
        tracing::info!(
            "Dev mode: Bypassing VDF proof verification for {}",
            reveal.name
        );
        return true;
    }

    if reveal.iterations < required_iterations {
        tracing::warn!(
            "Rejecting Reveal: Insufficient VDF iterations. Provided {}, Required {}",
            reveal.iterations,
            required_iterations
        );
        return false;
    }

    match engine.verify(&challenge, &reveal.vdf_proof, reveal.iterations) {
        Ok(true) => true,
        _ => {
            tracing::warn!("Rejecting Kademlia Reveal: Invalid VDF Proof");
            false
        }
    }
}

pub(crate) fn verify_authorized_kid(
    auth_kid: &kinetic_core::types::AuthorizedKid,
    active_reveal: Option<&kinetic_core::types::Reveal>,
) -> Result<(), KineticStoreError> {
    let reveal = active_reveal.ok_or_else(|| {
        tracing::warn!(
            "Rejecting AuthorizedKid: No active reveal found for name {}",
            auth_kid.name
        );
        KineticStoreError::InvalidKidSignature
    })?;

    let pubkey = ed25519_dalek::VerifyingKey::try_from(reveal.pubkey.as_slice())
        .map_err(|_| KineticStoreError::InvalidKidSignature)?;

    use ed25519_dalek::Verifier;
    let sig = ed25519_dalek::Signature::from_slice(&auth_kid.owner_signature)
        .map_err(|_| KineticStoreError::InvalidKidSignature)?;

    if pubkey.verify(&auth_kid.signable_bytes(), &sig).is_ok()
        && auth_kid.kid_doc.verify().is_ok()
    {
        tracing::info!(
            "KineticRecordStore::put accepted AuthorizedKid for {}",
            auth_kid.kid_doc.kid.as_str()
        );
        Ok(())
    } else {
        let err = KineticStoreError::InvalidKidSignature;
        tracing::warn!(
            error_code = "KIN-STORE-017",
            severity = ?err.severity(),
            "Rejecting AuthorizedKid: invalid signature or invalid document"
        );
        Err(err)
    }
}

pub(crate) fn verify_authorized_manifest(
    auth_manifest: &kinetic_core::types::AuthorizedManifest,
    active_reveal: Option<&kinetic_core::types::Reveal>,
) -> Result<(), KineticStoreError> {
    let reveal = active_reveal.ok_or_else(|| {
        tracing::warn!(
            "Rejecting AuthorizedManifest: No active reveal found for name {}",
            auth_manifest.name
        );
        KineticStoreError::InvalidManifestSignature
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
        tracing::warn!(
            error_code = "KIN-STORE-018",
            severity = ?err.severity(),
            "Rejecting AuthorizedManifest: invalid signature"
        );
        Err(err)
    }
}
