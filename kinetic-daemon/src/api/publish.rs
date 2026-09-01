//! HTTP REST API handlers for publishing Reveals, Commitments, Authorized KIDs, Manifests, and Governance actions.

use super::*;
use axum::{Json, extract::State, http::StatusCode};
use kinetic_core::types::RevealExt;

use tracing::{error, info};

/// Handles API requests to publish a `Reveal` to the DHT.
///
/// # Errors
///
/// Returns a tuple containing a `StatusCode` and an error JSON payload if the name is invalid,
/// the `Reveal` validation fails, or if publishing to the DHT fails.
pub async fn handle_publish_record(
    axum::extract::Extension(role): axum::extract::Extension<Role>,
    State(state): State<ApiState>,
    Json(req): Json<PublishRequest>,
) -> Result<Json<PublishResponse>, (StatusCode, Json<serde_json::Value>)> {
    if !role.can_publish() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(
                serde_json::json!({"error": "Insufficient privileges: Requires Publish or Admin role"}),
            ),
        ));
    }
    info!(
        "Received API publish request for name: {}",
        req.record.name()
    );

    // Normalize to canonical format
    let fqdn = kinetic_core::types::normalize_name(req.record.name());
    if let Err(e) = kinetic_core::types::is_valid_apex_name(&fqdn) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": format!("Invalid name: {}", e)})),
        ));
    }

    let mut name_record = req.record;

    // For Standard names, we need to validate and enforce Drand staleness.
    // Premium names bypass VDF staleness checks.
    let mut is_standard = false;
    let mut kyn = 0;
    if let kinetic_core::types::NameRecord::Standard(ref mut reveal) = name_record {
        reveal.name = fqdn.clone();
        if let Err(e) = reveal.validate() {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": format!("Invalid Reveal: {}", e)})),
            ));
        }
        is_standard = true;
        kyn = reveal.kyn;
    }

    // Finding 4 (High): Enforce drand staleness — reject Reveals whose VDF kyn is older
    // than RESQUARING_EPOCH_KYNS. Fetch the current beacon kyn, falling back to the
    // storage-cached value so offline-first nodes aren’t broken.
    let current_kyn: u64 = {
        let drand_client = kinetic_core::drand::DrandClient::new(Some(state.storage.clone()));
        match drand_client.fetch_latest().await {
            Ok(kyn) => kyn.kyn,
            Err(_) => {
                // Graceful fallback: read the last known kyn from storage.
                // If even that is unavailable, we allow the publish to proceed —
                // the DHT store layer will still enforce its own staleness check.
                let err = kinetic_core::error::DrandError::LiveFetchFailedFallback;
                tracing::warn!(
                    error_code = err.code(),
                    "{}", err
                );
                match drand_client.load_cached_kyn() {
                    Ok(kyn) => kyn.kyn,
                    Err(_) => 0,
                }
            }
        }
    };

    if is_standard && current_kyn > 0 {
        if kyn > current_kyn {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": format!(
                        "Reveal rejected: VDF kyn {} is in the future (current kyn: {}).",
                        kyn,
                        current_kyn
                    )
                })),
            ));
        }
        let age = current_kyn - kyn;
        if age > kinetic_core::types::RESQUARING_EPOCH_KYNS {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": format!(
                        "Reveal rejected: VDF kyn {} is {} kyns old (max allowed: {}). \
                         Please re-compute a fresh VDF proof.",
                        kyn,
                        age,
                        kinetic_core::types::RESQUARING_EPOCH_KYNS
                    )
                })),
            ));
        }
    }

    let payload_bytes = match serde_json::to_vec(&name_record) {
        Ok(b) => b,
        Err(e) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("Serialization failed: {}", e)})),
            ));
        }
    };
    let payload_clone = payload_bytes.clone();

    match state
        .network
        .publish_redundant_payload(&fqdn, payload_bytes)
        .await
    {
        Ok(_) => {
            info!(
                "Successfully queued payload for {} to the DHT network",
                fqdn
            );

            let owned_key = kinetic_core::constants::DB_PREFIX_OWNED_NAMES;
            let fqdn_clone = fqdn.clone();

            let _lock = crate::api::OWNED_NAMES_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            let mut owned = Vec::new();
            if let Ok(Some(bytes)) = state.storage.get(owned_key)
                && let Ok(names) = serde_json::from_slice::<Vec<String>>(&bytes)
            {
                owned = names;
            }
            if !owned.contains(&fqdn_clone) {
                owned.push(fqdn_clone.clone());
                if owned.len() > 10_000 {
                    let skip_count = owned.len() - 10_000;
                    owned = owned.into_iter().skip(skip_count).collect();
                }
                if let Ok(b) = serde_json::to_vec(&owned) {
                    let _ = state.storage.put(owned_key, &b);
                }
            }
            drop(_lock);
            info!(
                "Persisted {} to daemon storage for automatic Heartbeats",
                fqdn
            );

            // Persist the full Reveal so zone updates can re-sign without the original VDF params.
            let reveal_key = format!("{}{}", kinetic_core::constants::DB_PREFIX_REVEAL, fqdn);
            if let Ok(reveal_bytes) = serde_json::to_vec(&name_record) {
                let _ = state.storage.put(reveal_key.as_bytes(), &reveal_bytes);
                info!(
                    "Persisted Reveal for {} to daemon storage for future zone updates",
                    fqdn
                );
            }

            // Phase 4.2: Spawn a backgkyn task to verify quorum threshold
            let network = state.network.clone();
            let fqdn_clone = fqdn.clone();

            tokio::spawn(async move {
                tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
                match network.verify_quorum(&fqdn_clone, payload_clone).await {
                    Ok(quorum) if quorum >= 3 => {
                        tracing::info!(
                            "Quorum reached for {}: {}/5 nodes confirmed.",
                            fqdn_clone,
                            quorum
                        );
                    }
                    Ok(quorum) => {
                        let err = kinetic_core::error::PublishError::QuorumFailed(fqdn_clone.to_string(), quorum);
                        tracing::warn!(error_code = err.code(), "{}", err);
                    }
                    Err(e) => {
                        let err = kinetic_core::error::PublishError::QuorumCheckError(fqdn_clone.to_string(), e.to_string());
                        tracing::warn!(error_code = err.code(), "{}", err);
                    }
                }
            });

            Ok(Json(PublishResponse {
                status: "success".to_string(),
                message: "Payload accepted and routed to DHT network.".to_string(),
            }))
        }
        Err(e) => {
            let err = kinetic_core::error::PublishError::ZonePublishFailed(e.to_string());
            tracing::error!(error_code = err.code(), "{}", err);
            let api_err = kinetic_core::ApiError::from(e);
            Err((
                StatusCode::from_u16(api_err.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                Json(serde_json::to_value(api_err).unwrap_or_default()),
            ))
        }
    }
}

/// Handles API requests to commit a name registration hash to the DHT.
///
/// # Errors
///
/// Returns an error if the name is invalid, the commitment hash is all-zeros,
/// serialization fails, or DHT publishing fails.
pub async fn handle_publish_commit(
    axum::extract::Extension(role): axum::extract::Extension<Role>,
    State(state): State<ApiState>,
    Json(req): Json<kinetic_core::types::CommitRequest>,
) -> Result<Json<PublishResponse>, (StatusCode, Json<serde_json::Value>)> {
    if !role.can_publish() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(
                serde_json::json!({"error": "Insufficient privileges: Requires Publish or Admin role"}),
            ),
        ));
    }
    info!("Received API commit request for name: {}", req.name);

    // Normalize to canonical format
    let fqdn = kinetic_core::types::normalize_name(&req.name);
    if let Err(e) = kinetic_core::types::is_valid_apex_name(&fqdn) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": format!("Invalid name: {}", e)})),
        ));
    }

    // Finding 1 (Medium): Reject null/all-zero commitment hashes.
    // An all-zero hash is a trivial commitment that binds to nothing — any reveal whose
    // hash also produces zeros would match it, creating a commitment without any
    // cryptographic binding to the actual name or salt.
    if req.commitment.hash == [0u8; 32] {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "Commitment hash must not be all-zeros. \
                          Please provide a valid cryptographic commitment."
            })),
        ));
    }

    let payload_bytes = match serde_json::to_vec(&req.commitment) {
        Ok(b) => b,
        Err(e) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("Serialization failed: {}", e)})),
            ));
        }
    };

    // The commitment is stored as a special JSON payload (which the network differentiates based on struct parsing)
    // and broadcast to the same 5 derived DHT keys.
    match state
        .network
        .publish_redundant_payload(&fqdn, payload_bytes.clone())
        .await
    {
        Ok(_) => {
            info!(
                "Successfully queued Commitment for {} to the DHT network",
                fqdn
            );

            // Phase 4.2: Spawn a background task to verify quorum threshold
            let network = state.network.clone();
            let fqdn_clone = fqdn.clone();

            tokio::spawn(async move {
                tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
                match network.verify_quorum(&fqdn_clone, payload_bytes).await {
                    Ok(quorum) if quorum >= 3 => tracing::info!(
                        "Quorum reached for commitment of {}: {}/5 nodes confirmed.",
                        fqdn_clone,
                        quorum
                    ),
                    Ok(quorum) => {
                        let err = kinetic_core::error::PublishError::CommitmentQuorumFailed(fqdn_clone.to_string(), quorum);
                        tracing::warn!(error_code = err.code(), "{}", err);
                    },
                    Err(e) => {
                        let err = kinetic_core::error::PublishError::CommitmentQuorumCheckError(fqdn_clone.to_string(), e.to_string());
                        tracing::warn!(error_code = err.code(), "{}", err);
                    }
                }
            });

            Ok(Json(PublishResponse {
                status: "success".to_string(),
                message: "Commitment accepted and routed to DHT network.".to_string(),
            }))
        }
        Err(e) => {
            let err = kinetic_core::error::PublishError::CommitmentPublishFailed(e.to_string());
            tracing::error!(error_code = err.code(), "{}", err);
            let api_err = kinetic_core::ApiError::from(e);
            Err((
                StatusCode::from_u16(api_err.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                Json(serde_json::to_value(api_err).unwrap_or_default()),
            ))
        }
    }
}

/// Handles API requests to publish an `AuthorizedKid` (Kinetic Identifier) to the DHT.
///
/// # Errors
///
/// Returns an error if the KID signature is invalid, the owner authorization fails, or publishing fails.
pub async fn handle_publish_kid(
    axum::extract::Extension(role): axum::extract::Extension<Role>,
    State(state): State<ApiState>,
    Json(auth_kid): Json<kinetic_core::types::AuthorizedKid>,
) -> Result<Json<PublishResponse>, (StatusCode, Json<serde_json::Value>)> {
    if !role.can_publish() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "Insufficient privileges: Requires Publish or Admin role"})),
        ));
    }
    info!(
        "Received API publish request for KID: {}",
        auth_kid.kid_doc.kid.as_str()
    );

    // 1. Verify the underlying KID document mathematically
    if let Err(e) = auth_kid.kid_doc.verify() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": format!("Invalid KID signature: {}", e)})),
        ));
    }

    // 1b. Verify the wrapper signature against the registered name's Reveal locally.
    // If it fails here, we reject early and don't spam the DHT.
    let reveal_key = format!(
        "{}{}",
        kinetic_core::constants::DB_PREFIX_REVEAL,
        auth_kid.name
    );
    let is_authorized = match state.storage.get(reveal_key.as_bytes()) {
        Ok(Some(bytes)) => {
            if let Ok(record) = serde_json::from_slice::<kinetic_core::types::NameRecord>(&bytes) {
                kinetic_primitives::verify_mldsa(
                    record.pubkey(),
                    &auth_kid.signable_bytes(kinetic_core::constants::NETWORK_SALT),
                    &auth_kid.owner_signature,
                )
                .is_ok()
            } else {
                false
            }
        }
        _ => {
            let err = kinetic_core::error::PublishError::MissingLocalRevealForKid(auth_kid.name.clone());
            tracing::warn!(error_code = err.code(), "{}", err);
            true // If we don't have it cached, we let the network decide.
        }
    };

    if !is_authorized {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "Invalid authorization signature. The AuthorizedKid must be signed by the name's owner."})),
        ));
    }

    // 2. Serialize and Publish to DHT
    let payload_bytes = match serde_json::to_vec(&auth_kid) {
        Ok(b) => b,
        Err(e) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("Serialization failed: {}", e)})),
            ));
        }
    };
    let fqdn = auth_kid.kid_doc.kid.as_str().to_string(); // Use DID as the DHT key

    match state
        .network
        .publish_redundant_payload(&fqdn, payload_bytes)
        .await
    {
        Ok(_) => {
            info!("Successfully published KID {} to the DHT", fqdn);
            Ok(Json(PublishResponse {
                status: "success".to_string(),
                message: "AuthorizedKID accepted and routed to DHT".to_string(),
            }))
        }
        Err(e) => {
            let err = kinetic_core::error::PublishError::KidPublishFailed(e.to_string());
            error!(error_code = err.code(), "{}", err);
            let api_err = kinetic_core::ApiError::from(e);
            Err((
                StatusCode::from_u16(api_err.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                Json(serde_json::to_value(api_err).unwrap_or_default()),
            ))
        }
    }
}

/// Handles API requests to publish an `AuthorizedManifest` to the DHT.
///
/// # Errors
///
/// Returns an error if the local owner signature check fails, the corresponding KID Document
/// cannot be resolved or verified, or if publishing to the DHT fails.
pub async fn handle_publish_manifest(
    axum::extract::Extension(role): axum::extract::Extension<Role>,
    State(state): State<ApiState>,
    Json(auth_manifest): Json<kinetic_core::types::AuthorizedManifest>,
) -> Result<Json<PublishResponse>, (StatusCode, Json<serde_json::Value>)> {
    if !role.can_publish() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "Insufficient privileges: Requires Publish or Admin role"})),
        ));
    }
    let did_str = auth_manifest.manifest.kid.as_str();
    info!(
        "Received API publish request for Manifest of KID: {}",
        did_str
    );

    // 1b. Verify the wrapper signature against the registered name's Reveal locally.
    let reveal_key = format!(
        "{}{}",
        kinetic_core::constants::DB_PREFIX_REVEAL,
        auth_manifest.name
    );
    let is_authorized = match state.storage.get(reveal_key.as_bytes()) {
        Ok(Some(bytes)) => {
            if let Ok(record) = serde_json::from_slice::<kinetic_core::types::NameRecord>(&bytes) {
                kinetic_primitives::verify_mldsa(
                    record.pubkey(),
                    &auth_manifest.signable_bytes(kinetic_core::constants::NETWORK_SALT),
                    &auth_manifest.owner_signature,
                )
                .is_ok()
            } else {
                false
            }
        }
        _ => {
            let err = kinetic_core::error::PublishError::MissingLocalRevealForManifest(auth_manifest.name.clone());
            tracing::warn!(error_code = err.code(), "{}", err);
            true
        }
    };

    if !is_authorized {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "Invalid authorization signature. The AuthorizedManifest must be signed by the name's owner."})),
        ));
    }

    // 1. Resolve the KID Document from DHT to verify against
    // (Note: The DHT payload for a KID will now be an AuthorizedKid wrapper!)
    let kid_payload = match state.network.resolve_redundant_payload(did_str).await {
        Ok(p) => p,
        Err(e) => {
            let status = match e {
                kinetic_core::error::ResolutionError::NotFound { .. } => StatusCode::NOT_FOUND,
                kinetic_core::error::ResolutionError::Offline => StatusCode::SERVICE_UNAVAILABLE,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };
            return Err((status, Json(serde_json::json!({"error": format!("DHT lookup failed: {}", e)}))));
        }
    };

    let kid_doc: kinetic_kid::Document =
        match serde_json::from_slice::<kinetic_core::types::AuthorizedKid>(&kid_payload) {
            Ok(auth_kid) => auth_kid.kid_doc,
            Err(_) => {
                // Fallback for older raw Documents if any exist
                match serde_json::from_slice::<kinetic_kid::Document>(&kid_payload) {
                    Ok(doc) => doc,
                    Err(_) => {
                        return Err((
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(serde_json::json!({"error": "Invalid KID payload on DHT"})),
                        ));
                    }
                }
            }
        };

    // 2. Verify the manifest against the registered KID using network time
    let current_network_time = match kinetic_core::drand::DrandClient::new(Some(
        state.storage.clone(),
    ))
    .load_cached_kyn()
    {
        Ok(raw_kyn) => {
            use kinetic_core::types::clock::KynNetworkExt;
            kinetic_core::types::Kyn(raw_kyn.kyn).to_network_utime().0
        }
        Err(_) => std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    };
    if let Err(e) = auth_manifest
        .manifest
        .verify_at_time(&kid_doc, current_network_time)
    {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": format!("Invalid Manifest signature: {}", e)})),
        ));
    }

    // 3. Serialize and Publish to DHT under the derived manifest key
    let manifest_key = hex::encode(kinetic_primitives::sha256_hash(format!("{}#manifest", did_str).as_bytes()));

    let payload_bytes = match serde_json::to_vec(&auth_manifest) {
        Ok(b) => b,
        Err(e) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("Serialization failed: {}", e)})),
            ));
        }
    };
    match state
        .network
        .publish_redundant_payload(&manifest_key, payload_bytes)
        .await
    {
        Ok(_) => {
            info!("Successfully published Manifest for {} to the DHT", did_str);
            Ok(Json(PublishResponse {
                status: "success".to_string(),
                message: "Manifest accepted and routed to DHT".to_string(),
            }))
        }
        Err(e) => {
            let err = kinetic_core::error::PublishError::ManifestPublishFailed(e.to_string());
            error!(error_code = err.code(), "{}", err);
            let api_err = kinetic_core::ApiError::from(e);
            Err((
                StatusCode::from_u16(api_err.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                Json(serde_json::to_value(api_err).unwrap_or_default()),
            ))
        }
    }
}

/// Handles API requests to publish a `SignedGovernanceMessage` to the DHT/Gossip network.
///
/// # Errors
///
/// Returns an error if the governance message is invalid, quorum checks fail prematurely,
/// or publishing to the Gossipsub network fails.
pub async fn handle_publish_governance(
    axum::extract::Extension(role): axum::extract::Extension<Role>,
    State(state): State<ApiState>,
    Json(msg): Json<kinetic_core::governance::SignedGovernanceMessage>,
) -> Result<Json<PublishResponse>, (StatusCode, String)> {
    if !role.can_govern() {
        return Err((
            StatusCode::FORBIDDEN,
            "Insufficient privileges: Requires Governance or Admin role".to_string(),
        ));
    }
    tracing::info!("Received API publish request for Governance action");

    let current_kyn = {
        let drand_client = kinetic_core::drand::DrandClient::new(Some(state.storage.clone()));
        use kinetic_core::types::clock::KynNetworkExt;
        match drand_client.load_cached_kyn() {
            Ok(kyn) => kyn.kyn,
            Err(_) => match drand_client.fetch_latest().await {
                Ok(kyn) => kyn.kyn,
                Err(_) => kinetic_core::types::Kyn::now_local().0,
            }
        }
    };

    let is_valid = {
        let mut gov = kinetic_core::governance::GLOBAL_GOVERNANCE_STATE
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        match kinetic_core::governance::process_governance_message(&mut gov, &msg, current_kyn) {
            Ok(_) => {
                let path = kinetic_core::config::get_base_dir().join("governance.bin");
                if let Err(e) = gov.save_to_disk(&path) {
                    let err = kinetic_core::error::GovernanceError::StateSaveFailed;
                    tracing::error!(error_code = err.code(), "Failed to save modified governance state to disk: {}", e);
                }

                true
            }
            Err(e) => {
                tracing::warn!(error_code = e.code(), "Rejecting governance message via API: {}", e);
                return Err((
                    StatusCode::BAD_REQUEST,
                    format!("Invalid governance message: {}", e),
                ));
            }
        }
    };

    if !is_valid {
        return Err((
            StatusCode::BAD_REQUEST,
            "Governance message validation failed".to_string(),
        ));
    }

    // Serialize and gossip
    let payload_bytes = match serde_json::to_vec(&msg) {
        Ok(b) => b,
        Err(e) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Serialization failed: {}", e),
            ));
        }
    };

    let mut envelope = vec![kinetic_types::network::NetworkOpcode::Governance as u8];
    envelope.extend(payload_bytes);

    match state
        .network
        .broadcast_gossip(kinetic_core::constants::GOSSIP_TOPIC_GLOBAL, envelope)
        .await
    {
        Ok(_) => {
            tracing::info!("Successfully published Governance Message to the Gossip network");
            Ok(Json(PublishResponse {
                status: "success".to_string(),
                message: "Governance action accepted and routed to P2P network".to_string(),
            }))
        }
        Err(e) => {
            let err = kinetic_core::error::GovernanceError::P2pPublishFailed;
            tracing::error!(error_code = err.code(), "Failed to publish Governance Message to P2P network: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to broadcast: {}", e),
            ))
        }
    }
}
