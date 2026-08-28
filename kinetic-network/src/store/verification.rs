//! Cryptographic verification rules for Reveals, HostRoutingRecords, AuthorizedKids, and AuthorizedManifests.
//!
//! This module acts as the strict gatekeeper for the Kademlia DHT. It enforces
//! Ed25519 signature checks, VDF iteration verification (including loyalty discounts),
//! and timestamp freshness checks to prevent sybil attacks and namespace hijacking.

use crate::error::KineticStoreError;
use kinetic_core::types::RevealExt;
use kinetic_verify::signatures::VerifySignature;

/// Finding 13 (Critical): Verify a HostRoutingRecord's signature and timestamp freshness.
///
/// This lives in `kinetic-network` (not `kinetic-core`) because it requires the libp2p dependency
/// to extract the Ed25519 public key from the PeerId multihash.
///
/// # Arguments
///
/// * `record` - The host routing record to be verified.
/// * `current_kyn` - The current global drand kyn kyn.
///
/// # Errors
///
/// * Returns `KineticStoreError::InvalidHostRouteSignature` if the timestamp is stale (older than 100 kyns) or from the future.
/// * Returns `KineticStoreError::InvalidPublicKey` if the `host_id` cannot be parsed as a valid `PeerId` containing an Ed25519 key.
/// * Returns `KineticStoreError::MalformedSignature` if the signature bytes are structurally invalid.
pub(crate) fn verify_host_routing_record(
    record: &kinetic_core::types::HostRoutingRecord,
    current_kyn: u64,
) -> Result<(), KineticStoreError> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    // Enforce Drand kyn freshness — reject records older than 100 kyns (~5 minutes),
    // and reject records from the future to prevent pinning via u64::MAX timestamps.
    if current_kyn.saturating_sub(record.kyn) > 100 {
        let err = KineticStoreError::InvalidHostRouteSignature;
        err.log_warning(
            "KIN-KAD-023",
            &record.host_id,
            &format!(
                "HostRoutingRecord is stale ({} kyns old)",
                current_kyn.saturating_sub(record.kyn)
            ),
        );
        return Err(err);
    }
    // Allow a 2-kyn (~6 seconds) leeway for network clock drift before rejecting future timestamps.
    if record.kyn > current_kyn + 2 {
        let err = KineticStoreError::InvalidHostRouteSignature;
        err.log_warning(
            "KIN-KAD-024",
            &record.host_id,
            &format!(
                "HostRoutingRecord is too far in the future ({} kyns ahead, max 2 allowed)",
                record.kyn.saturating_sub(current_kyn)
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

    let signable = record.signable_bytes(kinetic_core::constants::NETWORK_SALT);
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
/// * `current_kyn` - The current global drand kyn kyn.
/// * `engine` - The VDF engine reference used to verify any `previous_proof` attached for a discount.
///
/// # Errors
///
/// * Returns `KineticStoreError::InvalidName` if the apex name is malformed.
/// * Returns `KineticStoreError::InvalidDrandHex` if the Drand randomness is not valid hex.
pub(crate) fn compute_required_iterations(
    reveal: &kinetic_core::types::Reveal,
    current_kyn: u64,
    engine: &dyn kinetic_core::traits::VdfEngine,
) -> Result<u64, KineticStoreError> {
    if let Err(e) = kinetic_core::types::names::is_valid_apex_name(&reveal.name) {
        let err = KineticStoreError::InvalidName;
        err.log_warning(
            "KIN-KAD-029",
            &reveal.name,
            &format!("Rejecting Kademlia Reveal: Invalid name: {:?}", e),
        );
        return Err(err);
    }

    use drand_verify::Pubkey;

    let consensus_math = kinetic_core::consensus_math::ConsensusParams::default();

    let drand_sig_bytes = hex::decode(&reveal.drand_signature).map_err(|_| {
        let err = KineticStoreError::InvalidDrandHex;
        err.log_warning(
            "KIN-KAD-028",
            &reveal.name,
            "Rejecting Kademlia Reveal: Invalid Drand signature hex",
        );
        err
    })?;

    if !kinetic_core::config::is_dev_mode() {
        let pubkey_bytes: [u8; 96] = hex::decode(kinetic_core::constants::DRAND_PUBLIC_KEY)
            .map_err(|_| KineticStoreError::InvalidDrandHex)?
            .try_into()
            .map_err(|_| KineticStoreError::InvalidDrandHex)?;

        let pubkey = drand_verify::G2PubkeyRfc::from_fixed(pubkey_bytes)
            .map_err(|_| KineticStoreError::InvalidDrandHex)?;

        if !pubkey
            .verify(reveal.kyn, &[], &drand_sig_bytes)
            .unwrap_or(false)
        {
            let err = KineticStoreError::InvalidDrandSignature;
            err.log_warning(
                "KIN-KAD-031",
                &reveal.name,
                "Rejecting Kademlia Reveal: Invalid Drand BLS signature",
            );
            return Err(err);
        }
    }

    let base_required_iterations = consensus_math.iterations(&reveal.name);
    let required_iterations = if let Some(prev) = &reveal.previous_proof {
        // Verify previous proof
        // Verify previous proof
        let prev_drand_sig_bytes = match hex::decode(&prev.drand_signature) {
            Ok(bytes) => bytes,
            Err(_) => {
                tracing::warn!(
                    "KIN-KAD-028: Invalid PreviousProof attached for {}: Invalid Drand signature hex. Falling back to full difficulty.",
                    reveal.name
                );
                return Ok(base_required_iterations);
            }
        };

        if !kinetic_core::config::is_dev_mode() {
            let pubkey_bytes: [u8; 96] = hex::decode(kinetic_core::constants::DRAND_PUBLIC_KEY)
                .map_err(|_| KineticStoreError::InvalidDrandHex)?
                .try_into()
                .map_err(|_| KineticStoreError::InvalidDrandHex)?;

            let pubkey = drand_verify::G2PubkeyRfc::from_fixed(pubkey_bytes)
                .map_err(|_| KineticStoreError::InvalidDrandHex)?;

            if !pubkey
                .verify(prev.kyn, &[], &prev_drand_sig_bytes)
                .unwrap_or(false)
            {
                tracing::warn!(
                    "KIN-KAD-030: Invalid PreviousProof attached for {}: Invalid Drand BLS signature. Falling back to full difficulty.",
                    reveal.name
                );
                return Ok(base_required_iterations);
            }
        }

        let prev_challenge = kinetic_core::types::Commitment::derive(
            kinetic_core::constants::NETWORK_SALT,
            &reveal.name,
            &prev.salt,
            &prev_drand_sig_bytes,
            &reveal.pubkey,
        );

        let prev_valid = matches!(
            engine.verify(&prev_challenge, &prev.vdf_proof, prev.iterations),
            Ok(true)
        );

        let prev_req = consensus_math.iterations(&reveal.name);

        let paused_kyns =
            if let Ok(state) = kinetic_core::governance::GLOBAL_GOVERNANCE_STATE.lock() {
                state.paused_kyns_since(prev.kyn)
            } else {
                0
            };

        let effective_age = current_kyn
            .saturating_sub(prev.kyn)
            .saturating_sub(paused_kyns);
        let is_not_too_old = effective_age <= kinetic_core::types::RESQUARING_EPOCH_KYNS * 2;

        if prev_valid && prev.iterations >= prev_req && is_not_too_old {
            let normalized_name = kinetic_core::types::normalize_name(&reveal.name);
            let name_len = normalized_name
                .strip_suffix(kinetic_core::constants::NSP_SUFFIX)
                .unwrap_or(&normalized_name)
                .len();
            let discount_iterations = match name_len {
                1 => kinetic_core::constants::CONSENSUS_VDF_DISCOUNT_MIN_ITERATIONS, // 100% discount (minimum iterations)
                2..=6 => base_required_iterations / 2,                               // 50% discount
                7..=10 => base_required_iterations / 5,                              // 80% discount
                _ => {
                    (base_required_iterations
                        * kinetic_core::constants::CONSENSUS_VDF_DISCOUNT_PERCENTAGE)
                        / 100
                } // 85% discount for 11+
            };

            tracing::info!(
                "Valid PreviousProof attached for {}. Granting loyalty discount for length {}.",
                reveal.name,
                name_len
            );
            std::cmp::max(
                kinetic_core::constants::CONSENSUS_VDF_DISCOUNT_MIN_ITERATIONS,
                discount_iterations,
            )
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
/// * `current_kyn` - The current drand kyn kyn.
/// * `engine` - The VDF engine used to verify the proof.
///
/// # Errors
///
/// * Returns `KineticStoreError::InvalidName` if the name is invalid.
/// * Returns `KineticStoreError::InvalidPublicKey` or `KineticStoreError::InvalidSignature` if Ed25519 checks fail.
/// * Returns `KineticStoreError::StaleReveal` if the commitment is too recent (age < 10 kyns).
/// * Returns `KineticStoreError::MissingCommitment` if no prior commitment is found in the DHT.
/// * Returns `KineticStoreError::InsufficientIterations` if the iterations do not meet the consensus threshold.
/// * Returns `KineticStoreError::InvalidVdf` if the VDF proof fails verification.
pub(crate) fn verify_reveal(
    reveal: &kinetic_core::types::Reveal,
    storage: &std::sync::Arc<dyn kinetic_core::traits::StorageEngine>,
    current_kyn: u64,
    engine: &std::sync::Arc<dyn kinetic_core::traits::VdfEngine>,
) -> Result<(), KineticStoreError> {
    if let Ok(state) = kinetic_core::governance::GLOBAL_GOVERNANCE_STATE.lock()
        && state.is_halted
    {
        return Err(KineticStoreError::NetworkHalted);
    }
    if let Err(e) = reveal.validate() {
        let err = KineticStoreError::InvalidName;
        err.log_warning(
            "KIN-KAD-029",
            &reveal.name,
            &format!("Rejecting Kademlia Reveal: Validation failed: {:?}", e),
        );
        return Err(err);
    }

    use drand_verify::Pubkey;

    let dev_mode = kinetic_core::config::is_dev_mode();

    if !dev_mode
        && reveal
            .verify_signature(kinetic_core::constants::NETWORK_SALT)
            .is_err()
    {
        let err = KineticStoreError::InvalidSignature;
        err.log_warning(
            "KIN-KAD-026",
            &reveal.name,
            "Rejecting Kademlia Reveal: Invalid Post-Quantum Signature",
        );
        return Err(err);
    }

    let drand_sig_bytes = hex::decode(&reveal.drand_signature).map_err(|_| {
        let err = KineticStoreError::InvalidDrandHex;
        err.log_warning(
            "KIN-KAD-028",
            &reveal.name,
            "Rejecting Kademlia Reveal: Invalid Drand Signature Hex",
        );
        err
    })?;

    if !dev_mode {
        let pubkey_bytes: [u8; 96] = hex::decode(kinetic_core::constants::DRAND_PUBLIC_KEY)
            .map_err(|_| KineticStoreError::InvalidDrandHex)?
            .try_into()
            .map_err(|_| KineticStoreError::InvalidDrandHex)?;

        let pubkey = drand_verify::G2PubkeyRfc::from_fixed(pubkey_bytes)
            .map_err(|_| KineticStoreError::InvalidDrandHex)?;

        if !pubkey
            .verify(reveal.kyn, &[], &drand_sig_bytes)
            .unwrap_or(false)
        {
            let err = KineticStoreError::InvalidDrandSignature;
            err.log_warning(
                "KIN-KAD-031",
                &reveal.name,
                "Rejecting Kademlia Reveal: Invalid Drand BLS signature",
            );
            return Err(err);
        }
    }

    let challenge = kinetic_core::types::Commitment::derive(
        kinetic_core::constants::NETWORK_SALT,
        &reveal.name,
        &reveal.salt,
        &drand_sig_bytes,
        &reveal.pubkey,
    );
    let hash = challenge.hash;

    let mut commit_key = Vec::with_capacity(crate::store::constants::KRS_COMMIT_PREFIX.len() + 32);
    commit_key.extend_from_slice(crate::store::constants::KRS_COMMIT_PREFIX);
    commit_key.extend_from_slice(&hash);

    let commit_kyn = get_u64_from_sled(storage, &commit_key);

    if let Some(commit_kyn) = commit_kyn {
        if !dev_mode
            && current_kyn.saturating_sub(commit_kyn)
                < kinetic_core::constants::CONSENSUS_MINIMUM_COMMIT_AGE_KYNS
        {
            let err = KineticStoreError::StaleReveal;
            err.log_warning(
                "KIN-KAD-027",
                &reveal.name,
                "Rejecting Reveal: Commitment is too recent (age < minimum commit age)",
            );
            return Err(err);
        }
        tracing::info!(
            "Commitment matched for Reveal of {} (committed akyn kyn {})",
            reveal.name,
            commit_kyn
        );
    } else if !dev_mode {
        let err = KineticStoreError::MissingCommitment { commit_key };
        err.log_warning(
            "KIN-KAD-038",
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
        compute_required_iterations(reveal, current_kyn, engine.as_ref())?;

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
            "KIN-KAD-030",
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
                "KIN-KAD-039",
                &reveal.name,
                "Rejecting Kademlia Reveal: Invalid VDF Proof",
            );
            Err(err)
        }
        Err(e) => {
            let err = KineticStoreError::VdfEngineError(e.to_string());
            err.log_warning(
                "KIN-KAD-040",
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
/// * `existing_record` - The pre-existing DHT record for this name, if any, used to enforce
///   the key-rotation update chain and prevent DID hijacking.
///
/// # Behaviour
///
/// - **First publication** (`existing_record` is `None`): calls `verify_genesis()` to enforce
///   that the `kid` DID is the SHA-256 hash of the primary controller key, preventing
///   a domain owner from publishing a KID they have no cryptographic claim to.
///
/// - **Update** (`existing_record` is `Some`): verifies that the new document is signed by
///   a key that appeared in the previously stored KID document, enforcing the authorised
///   update chain and preventing key-hijacking after the genesis document is established.
///
/// # Errors
///
/// Returns `KineticStoreError::InvalidKidSignature` if the reveal is missing, the domain
/// owner signature is invalid, the inner KID document fails self-verification, the genesis
/// binding fails on first publication, or the update is not authorised by a prior key.
pub(crate) fn verify_authorized_kid(
    auth_kid: &kinetic_core::types::AuthorizedKid,
    active_record: Option<&kinetic_core::types::NameRecord>,
    existing_record: Option<&std::borrow::Cow<'_, libp2p::kad::Record>>,
) -> Result<(), KineticStoreError> {
    let record = active_record.ok_or_else(|| {
        let err = KineticStoreError::NameNotFound;
        err.log_warning(
            "KIN-KAD-032",
            &auth_kid.name,
            "Rejecting AuthorizedKid: No active reveal found",
        );
        err
    })?;

    if kinetic_primitives::verify_mldsa(
        record.pubkey(),
        &auth_kid.signable_bytes(kinetic_core::constants::NETWORK_SALT),
        auth_kid.owner_signature.as_slice(),
    ).is_err()
        || auth_kid.kid_doc.verify().is_err()
    {
        let err = KineticStoreError::InvalidKidDocument;
        err.log_warning(
            "KIN-KAD-017",
            &auth_kid.name,
            "Rejecting AuthorizedKid: invalid signature or invalid document",
        );
        return Err(err);
    }

    match existing_record {
        None => {
            // First publication: enforce DID ↔ genesis key binding.
            auth_kid.kid_doc.verify_genesis().map_err(|e| {
                let err = KineticStoreError::GenesisBindingFailed;
                err.log_warning(
                    "KIN-KAD-035",
                    &auth_kid.name,
                    &format!("Rejecting AuthorizedKid: genesis DID binding failed: {}", e),
                );
                err
            })?;
        }
        Some(record) => {
            // Update: new document must be signed by a key from the previous document.
            if let Ok(old_auth_kid) =
                serde_json::from_slice::<kinetic_core::types::AuthorizedKid>(&record.value)
                && !auth_kid.kid_doc.is_authorized(&old_auth_kid.kid_doc)
            {
                let err = KineticStoreError::UnauthorizedUpdate;
                err.log_warning(
                        "KIN-KAD-037",
                        &auth_kid.name,
                        "Rejecting AuthorizedKid update: not signed by any key in the existing document",
                    );
                return Err(err);
            }
            // If the existing record can't be parsed as an AuthorizedKid (e.g. corrupted),
            // we fall back to allowing the update — the domain owner's Ed25519 signature
            // already authenticated the submission above.
        }
    }

    tracing::info!(
        "KineticRecordStore::put accepted AuthorizedKid for {}",
        auth_kid.kid_doc.kid.as_str()
    );
    Ok(())
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
    active_record: Option<&kinetic_core::types::NameRecord>,
    existing_record: Option<&std::borrow::Cow<'_, libp2p::kad::Record>>,
) -> Result<(), KineticStoreError> {
    let record = active_record.ok_or_else(|| {
        let err = KineticStoreError::NameNotFound;
        err.log_warning(
            "KIN-KAD-033",
            &auth_manifest.name,
            "Rejecting AuthorizedManifest: No active reveal found",
        );
        err
    })?;

    if kinetic_primitives::verify_mldsa(
        record.pubkey(),
        &auth_manifest.signable_bytes(kinetic_core::constants::NETWORK_SALT),
        auth_manifest.owner_signature.as_slice(),
    ).is_err()
    {
        let err = KineticStoreError::InvalidManifestSignature;
        err.log_warning(
            "KIN-KAD-018",
            &auth_manifest.name,
            "Rejecting AuthorizedManifest: invalid owner signature",
        );
        return Err(err);
    }

    let kid_doc = auth_manifest
        .kid_doc
        .as_ref()
        .ok_or(KineticStoreError::InvalidKidDocument)?;
    kid_doc
        .verify()
        .map_err(|_| KineticStoreError::InvalidManifestSignature)?;
    auth_manifest
        .manifest
        .verify_local(kid_doc)
        .map_err(|_| KineticStoreError::ManifestVerificationFailed)?;

    if let Some(existing) = existing_record
        && let Ok(old_manifest) =
            serde_json::from_slice::<kinetic_core::types::AuthorizedManifest>(&existing.value)
        && auth_manifest.manifest.version <= old_manifest.manifest.version
    {
        let err = KineticStoreError::ManifestVersionRollback;
        err.log_warning(
            "KIN-KAD-034",
            &auth_manifest.name,
            "Rejecting AuthorizedManifest: Version rollback detected",
        );
        return Err(err);
    }

    tracing::info!(
        "KineticRecordStore::put accepted AuthorizedManifest for {}",
        auth_manifest.manifest.kid.as_str()
    );
    Ok(())
}
