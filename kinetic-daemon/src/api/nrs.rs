//! HTTP REST API handlers for publishing Reveals, Commitments, Authorized KIDs, Manifests, and Governance actions.

use super::*;
use axum::{
    Json,
    extract::{Extension, Path, State},
    http::StatusCode,
};
use kinetic_core::traits::KynProvider;
use kinetic_core::types::RevealExt;

use kinetic_verify::signatures::VerifySignature;

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
    if !role.can_nrs() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(
                serde_json::json!({"error": "Insufficient privileges: Requires Nrs or Admin role"}),
            ),
        ));
    }
    tracing::info!(
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
        let kyn_provider =
            kinetic_network::client::drand::DrandProvider::new(Some(state.storage.clone()));
        match kyn_provider.fetch_latest().await {
            Ok(kyn) => kyn.kyn,
            Err(_) => {
                // Graceful fallback: read the last known kyn from storage.
                // If even that is unavailable, we allow the publish to proceed —
                // the DHT store layer will still enforce its own staleness check.
                let err = kinetic_core::error::KynProviderError::LiveFetchFailedFallback;
                tracing::warn!(error_code = err.code(), "{}", err);
                match kyn_provider.load_cached_kyn() {
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
            tracing::info!(
                "Successfully queued payload for {} to the DHT network",
                fqdn
            );

            let owned_key = kinetic_core::constants::DB_PREFIX_OWNED_NAMES;
            let fqdn_clone = fqdn.clone();

            let _lock = crate::api::OWNED_NAMES_LOCK
                .lock()
                .unwrap_or_else(|e| e.into_inner());
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
            tracing::info!(
                "Persisted {} to daemon storage for automatic Heartbeats",
                fqdn
            );

            // Persist the full Reveal so zone updates can re-sign without the original VDF params.
            let reveal_key = format!("{}{}", kinetic_core::constants::DB_PREFIX_REVEAL, fqdn);
            if let Ok(reveal_bytes) = serde_json::to_vec(&name_record) {
                let _ = state.storage.put(reveal_key.as_bytes(), &reveal_bytes);
                tracing::info!(
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
                        let err = kinetic_core::error::PublishError::QuorumFailed(
                            fqdn_clone.to_string(),
                            quorum,
                        );
                        tracing::warn!(error_code = err.code(), "{}", err);
                    }
                    Err(e) => {
                        let err = kinetic_core::error::PublishError::QuorumCheckError(
                            fqdn_clone.to_string(),
                            e.to_string(),
                        );
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
            let api_err = kinetic_rpc::ApiError::from(e);
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
    if !role.can_nrs() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(
                serde_json::json!({"error": "Insufficient privileges: Requires Nrs or Admin role"}),
            ),
        ));
    }
    tracing::info!("Received API commit request for name: {}", req.name);

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
            tracing::info!(
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
                        let err = kinetic_core::error::PublishError::CommitmentQuorumFailed(
                            fqdn_clone.to_string(),
                            quorum,
                        );
                        tracing::warn!(error_code = err.code(), "{}", err);
                    }
                    Err(e) => {
                        let err = kinetic_core::error::PublishError::CommitmentQuorumCheckError(
                            fqdn_clone.to_string(),
                            e.to_string(),
                        );
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
            let api_err = kinetic_rpc::ApiError::from(e);
            Err((
                StatusCode::from_u16(api_err.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                Json(serde_json::to_value(api_err).unwrap_or_default()),
            ))
        }
    }
}

/// Handles API requests to resolve a Kinetic name.
/// Searches the DHT and falls back to a local daemon backup if the name cannot be found on the network.
///
/// # Errors
///
/// Returns a standard Kinetic ApiError if the name is not found
/// or if resolution fails due to network offline states or data corruption.
pub async fn handle_resolve_name(
    State(state): State<ApiState>,
    Path(name): Path<String>,
) -> Result<Json<kinetic_core::types::NameRecord>, crate::api::error::AppError> {
    let fqdn = kinetic_core::types::normalize_name(&name);

    if kinetic_core::types::names::is_reserved_name(&fqdn) {
        let apex = kinetic_core::types::names::extract_apex_name(&fqdn);
        let apex_no_tld = apex.trim_end_matches(kinetic_core::constants::NSP_SUFFIX);
        let local_zone_file = kinetic_local::config::get_zones_dir()
            .join("local")
            .join(format!("{}.json", apex_no_tld));

        if let Ok(content) = std::fs::read_to_string(&local_zone_file)
            && let Ok(zone) = serde_json::from_str::<kinetic_core::types::NrsZone>(&content)
        {
            let payload = serde_json::to_vec(&zone).unwrap_or_default();
            let dummy_json = serde_json::json!({
                "owner_kid": "reserved_local",
                "payload": payload,
                "signature": [],
                "timestamp": 0
            });
            if let Ok(record) =
                serde_json::from_value::<kinetic_core::types::NameRecord>(dummy_json)
            {
                return Ok(Json(record));
            }
        }

        return Err(kinetic_core::error::ResolutionError::NotFound {
            name: fqdn,
            peers_queried: 0,
        }
        .into());
    }

    let record = match state.network.resolve_redundant_payload(&fqdn).await {
        Ok(payload) => {
            let record = serde_json::from_slice::<kinetic_core::types::NameRecord>(&payload)
                .map_err(|_| kinetic_core::error::ResolutionError::Internal {
                    message: "Invalid NameRecord payload on DHT".to_string(),
                    source: None,
                })?;

            let dev_mode = kinetic_core::config::is_dev_mode();
            if !dev_mode
                && let Err(e) = record.verify_signature(kinetic_core::constants::NETWORK_SALT)
            {
                let err = kinetic_core::error::ResolutionError::SignatureVerificationFailed(
                    e.to_string(),
                );
                tracing::warn!(error_code = err.code(), "{}", err);
                return Err(crate::api::error::AppError(err.into()));
            }
            record
        }
        Err(kinetic_core::error::ResolutionError::NotFound { .. }) => {
            // Fallback to local storage if DHT lookup fails or returns nothing
            // This rescues users who lost their local reveal.json and the DHT dropped their record
            let reveal_key = format!("{}{}", kinetic_core::constants::DB_PREFIX_REVEAL, fqdn);
            match state.storage.get(reveal_key.as_bytes()) {
                Ok(Some(bytes)) => {
                    serde_json::from_slice::<kinetic_core::types::NameRecord>(&bytes).map_err(
                        |e| {
                            tracing::error!(
                                error = ?kinetic_core::error::StorageError::DeserializationFailed(e.to_string()),
                                name = %fqdn,
                                "{}",
                                kinetic_core::error::StorageError::DeserializationFailed(e.to_string()).user_message()
                            );
                            kinetic_core::error::ResolutionError::Internal {
                                message: "Stored registration data is corrupted.".to_string(),
                                source: None,
                            }
                        },
                    )?
                }
                _ => {
                    return Err(kinetic_core::error::ResolutionError::NotFound {
                        name: fqdn,
                        peers_queried: 0,
                    }
                    .into());
                }
            }
        }
        Err(e) => {
            tracing::warn!(error_code = e.code(), "Resolution error: {}", e.to_string());
            return Err(e.into());
        }
    };

    Ok(Json(record))
}

/// Handles requests to verify DHT quorum for a specific name record payload.
pub async fn handle_verify_quorum(
    State(state): State<ApiState>,
    Path(name): Path<String>,
    Json(record): Json<kinetic_core::types::NameRecord>,
) -> Result<Json<serde_json::Value>, crate::api::error::AppError> {
    let fqdn = kinetic_core::types::normalize_name(&name);

    let payload = match serde_json::to_vec(&record) {
        Ok(b) => b,
        Err(_) => {
            return Err(crate::api::error::AppError::from(
                kinetic_core::error::RestApiError::BadRequest(
                    "Invalid NameRecord payload".to_string(),
                ),
            ));
        }
    };

    match state.network.verify_quorum(&fqdn, payload).await {
        Ok(count) => Ok(Json(serde_json::json!({
            "name": fqdn,
            "quorum_count": count
        }))),
        Err(e) => Err(crate::api::error::AppError::from(e)),
    }
}
/// Represents the status of a reserved name in the local network configuration.
#[derive(serde::Serialize)]
pub struct ReservedNameStatus {
    /// The reserved name (e.g., "example", "localhost").
    pub name: String,
    /// True if a local zone override file exists for this name.
    pub active: bool,
}

/// Handles API requests to get the list of reserved names and their active local status.
pub async fn handle_get_reserved_names()
-> Result<Json<Vec<ReservedNameStatus>>, crate::api::error::AppError> {
    let local_dir = kinetic_local::config::get_zones_dir().join("local");

    let mut statuses = Vec::new();
    for r in kinetic_core::types::RESERVED_NAMES {
        let path = local_dir.join(format!("{}.json", r));
        statuses.push(ReservedNameStatus {
            name: r.to_string(),
            active: path.exists(),
        });
    }

    Ok(Json(statuses))
}

/// Handles API requests to retrieve a local zone file for a given name.
///
/// # Errors
///
/// Returns an error if the zone file does not exist or has an invalid format.
pub async fn handle_get_zone(
    Path(name): Path<String>,
) -> Result<Json<serde_json::Value>, crate::api::error::AppError> {
    let fqdn = kinetic_core::types::normalize_name(&name);
    kinetic_core::types::is_valid_apex_name(&fqdn)?;

    let path = kinetic_local::config::get_zones_dir().join(format!("{}.json", fqdn));
    if let Ok(content) = std::fs::read_to_string(path) {
        match serde_json::from_str::<serde_json::Value>(&content) {
            Ok(zone) => return Ok(Json(zone)),
            Err(e) => {
                return Err(crate::api::error::AppError(
                    kinetic_core::error::NrsError::ParseError(e).into(),
                ));
            }
        }
    }
    Err(crate::api::error::AppError::from(
        kinetic_core::error::RestApiError::NotFound,
    ))
}

/// Handles API requests to save changes to a local zone file without broadcasting to the network.
///
/// # Errors
///
/// Returns an error if serialization fails or if the daemon lacks filesystem write permissions.
pub async fn handle_post_zone(
    Extension(role): Extension<Role>,
    Path(name): Path<String>,
    Json(zone): Json<kinetic_core::types::NrsZone>,
) -> Result<Json<serde_json::Value>, crate::api::error::AppError> {
    if !role.can_nrs() {
        return Err(crate::api::error::AppError::from(
            kinetic_core::error::RestApiError::InsufficientPrivileges,
        ));
    }
    let fqdn = kinetic_core::types::normalize_name(&name);
    kinetic_core::types::is_valid_apex_name(&fqdn)?;

    let path = kinetic_local::config::get_zones_dir().join(format!("{}.json", fqdn));
    let _ = std::fs::create_dir_all(kinetic_local::config::get_zones_dir());

    let content = match serde_json::to_string_pretty(&zone) {
        Ok(c) => c,
        Err(e) => {
            return Err(crate::api::error::AppError(
                kinetic_core::error::StorageError::WriteFailed(format!(
                    "Serialization failed: {}",
                    e
                ))
                .into(),
            ));
        }
    };
    if let Err(e) = std::fs::write(&path, content) {
        let sys_err = kinetic_core::error::SystemError::DiskPersistenceFailed(e.to_string());
        return Err(crate::api::error::AppError(kinetic_rpc::ApiError {
            error_type: format!(
                "{}/errors/{}",
                kinetic_core::constants::DOCS_URL,
                sys_err.code()
            ),
            title: "Internal Server Error".to_string(),
            status: 500,
            detail: sys_err.user_message(),
            instance: None,
            code: sys_err.code().to_string(),
            retryable: sys_err.is_retryable(),
            details: serde_json::Value::Null,
            request_id: "".to_string(),
        }));
    }

    Ok(Json(serde_json::json!({ "success": true })))
}

/// Handles API requests to cryptographically sign a local zone file and publish the updated Reveal to the DHT.
///
/// # Errors
///
/// Returns an error if the zone file or the local registration record is missing/corrupted,
/// if the daemon identity key cannot be loaded, or if the DHT publish operation fails.
pub async fn handle_publish_zone(
    Extension(role): Extension<Role>,
    State(state): State<ApiState>,
    Path(name): Path<String>,
) -> Result<Json<serde_json::Value>, crate::api::error::AppError> {
    if !role.can_nrs() {
        return Err(crate::api::error::AppError::from(
            kinetic_core::error::RestApiError::InsufficientPrivileges,
        ));
    }
    let fqdn = kinetic_core::types::normalize_name(&name);
    kinetic_core::types::is_valid_apex_name(&fqdn)?;

    // 1. Read the current zone file
    let zone_path = kinetic_local::config::get_zones_dir().join(format!("{}.json", fqdn));
    let content = match std::fs::read_to_string(&zone_path) {
        Ok(c) => c,
        Err(_) => {
            return Err(crate::api::error::AppError::from(
                kinetic_core::error::RestApiError::NotFound,
            ));
        }
    };
    let zone: kinetic_core::types::NrsZone = match serde_json::from_str(&content) {
        Ok(z) => z,
        Err(e) => {
            return Err(crate::api::error::AppError(
                kinetic_core::error::NrsError::ParseError(e).into(),
            ));
        }
    };

    // 2. Load the persisted Reveal (stored at registration time)
    let reveal_key = format!("{}{}", kinetic_core::constants::DB_PREFIX_REVEAL, fqdn);
    let reveal_bytes = match state.storage.get(reveal_key.as_bytes()) {
        Ok(Some(b)) => b,
        _ => {
            return Err(crate::api::error::AppError(kinetic_rpc::ApiError::from(
                kinetic_core::error::RegistrationError::NotRegisteredLocal {
                    name: fqdn.to_string(),
                },
            )));
        }
    };
    let mut record: kinetic_core::types::NameRecord = match serde_json::from_slice(&reveal_bytes) {
        Ok(r) => r,
        Err(_) => {
            return Err(crate::api::error::AppError(
                kinetic_core::error::StorageError::DeserializationFailed(
                    "Stored registration data is corrupted.".to_string(),
                )
                .into(),
            ));
        }
    };

    // 3. Load the daemon keypair and re-sign with the updated payload
    let identity_path = kinetic_local::config::get_base_dir().join("identity.key");
    let keypair = match kinetic_local::identity::load_keypair(&identity_path) {
        Ok(k) => k,
        Err(e) => return Err(crate::api::error::AppError(e.into())),
    };

    let pubkey_bytes = keypair.pubkey_bytes();
    if record.pubkey() != pubkey_bytes.as_slice() {
        return Err(crate::api::error::AppError(
            kinetic_core::error::IdentityError::PubkeyMismatch(
                "The daemon key does not match the owner key for this name registration."
                    .to_string(),
            )
            .into(),
        ));
    }

    let payload = match serde_json::to_vec(&zone) {
        Ok(v) => v,
        Err(e) => {
            let err = kinetic_core::error::PublishError::ZoneSerializationFailed(e.to_string());
            tracing::error!(error_code = err.code(), "{}", err);
            return Err(err.into());
        }
    };

    match &mut record {
        kinetic_core::types::NameRecord::Standard(r) => {
            r.payload = payload;
            let signable = r.signable_bytes(kinetic_core::constants::NETWORK_SALT);
            r.signature = keypair.sign(&signable);
        }
        kinetic_core::types::NameRecord::Prime {
            name,
            payload: p,
            signature: s,
            ..
        }
        | kinetic_core::types::NameRecord::Infra {
            name,
            payload: p,
            signature: s,
            ..
        } => {
            *p = payload.clone();
            let mut signable = Vec::new();
            signable.extend_from_slice(&(name.len() as u32).to_be_bytes());
            signable.extend_from_slice(name.as_bytes());
            signable.extend_from_slice(&(payload.len() as u32).to_be_bytes());
            signable.extend_from_slice(&payload);
            signable.extend_from_slice(kinetic_core::constants::NETWORK_SALT);

            *s = keypair.sign(&signable);
        }
    }

    // 4. Update the stored Reveal so future zone publishes reflect the latest payload
    if let Ok(updated_bytes) = serde_json::to_vec(&record) {
        let _ = state.storage.put(reveal_key.as_bytes(), &updated_bytes);
    }

    // 5. Serialize and publish to the DHT
    let dht_payload = match serde_json::to_vec(&record) {
        Ok(b) => b,
        Err(e) => {
            return Err(kinetic_core::error::PublishError::Internal {
                message: format!("Serialization error: {}", e),
                source: None,
            }
            .into());
        }
    };
    match state
        .network
        .publish_redundant_payload(&fqdn, dht_payload)
        .await
    {
        Ok(_) => {
            tracing::info!("Zone published to DHT for {}", fqdn);
            Ok(Json(
                serde_json::json!({ "success": true, "message": "Zone published to the Kinetic DHT network." }),
            ))
        }
        Err(e) => Err(e.into()),
    }
}

/// Handles API requests to save changes to a reserved local zone file (e.g. example.kin).
pub async fn handle_post_local_zone(
    Extension(role): Extension<Role>,
    Path(name): Path<String>,
    Json(zone): Json<kinetic_core::types::NrsZone>,
) -> Result<Json<serde_json::Value>, crate::api::error::AppError> {
    if !role.can_nrs() {
        return Err(crate::api::error::AppError::from(
            kinetic_core::error::RestApiError::InsufficientPrivileges,
        ));
    }

    let fqdn = kinetic_core::types::normalize_name(&name);
    if !kinetic_core::types::names::is_reserved_name(&fqdn) {
        return Err(crate::api::error::AppError::from(
            kinetic_core::error::RestApiError::BadRequest(
                "This endpoint is strictly for reserved local names (e.g. example.kin)."
                    .to_string(),
            ),
        ));
    }

    let apex = kinetic_core::types::names::extract_apex_name(&fqdn);
    let apex_no_tld = apex.trim_end_matches(kinetic_core::constants::NSP_SUFFIX);

    let local_dir = kinetic_local::config::get_zones_dir().join("local");
    let _ = std::fs::create_dir_all(&local_dir);
    let path = local_dir.join(format!("{}.json", apex_no_tld));

    let content = match serde_json::to_string_pretty(&zone) {
        Ok(c) => c,
        Err(e) => {
            return Err(crate::api::error::AppError(
                kinetic_core::error::StorageError::WriteFailed(format!(
                    "Serialization failed: {}",
                    e
                ))
                .into(),
            ));
        }
    };

    if let Err(e) = std::fs::write(&path, content) {
        let sys_err = kinetic_core::error::SystemError::DiskPersistenceFailed(e.to_string());
        return Err(crate::api::error::AppError(kinetic_rpc::ApiError {
            error_type: format!(
                "{}/errors/{}",
                kinetic_core::constants::DOCS_URL,
                sys_err.code()
            ),
            title: "Internal Server Error".to_string(),
            status: 500,
            detail: sys_err.user_message(),
            instance: None,
            code: sys_err.code().to_string(),
            retryable: sys_err.is_retryable(),
            details: serde_json::Value::Null,
            request_id: "".to_string(),
        }));
    }

    Ok(Json(serde_json::json!({ "success": true })))
}

/// Handles API requests to delete a reserved local zone file.
pub async fn handle_delete_local_zone(
    Extension(role): Extension<Role>,
    Path(name): Path<String>,
) -> Result<Json<serde_json::Value>, crate::api::error::AppError> {
    if !role.can_nrs() {
        return Err(crate::api::error::AppError::from(
            kinetic_core::error::RestApiError::InsufficientPrivileges,
        ));
    }

    let fqdn = kinetic_core::types::normalize_name(&name);
    if !kinetic_core::types::names::is_reserved_name(&fqdn) {
        return Err(crate::api::error::AppError::from(
            kinetic_core::error::RestApiError::BadRequest(
                "This endpoint is strictly for reserved local names (e.g. example.kin)."
                    .to_string(),
            ),
        ));
    }

    let apex = kinetic_core::types::names::extract_apex_name(&fqdn);
    let apex_no_tld = apex.trim_end_matches(kinetic_core::constants::NSP_SUFFIX);

    let path = kinetic_local::config::get_zones_dir()
        .join("local")
        .join(format!("{}.json", apex_no_tld));

    if path.exists()
        && let Err(e) = std::fs::remove_file(&path)
    {
        let sys_err = kinetic_core::error::SystemError::DiskPersistenceFailed(format!(
            "File delete failed: {}",
            e
        ));
        return Err(crate::api::error::AppError(kinetic_rpc::ApiError {
            error_type: format!(
                "{}/errors/{}",
                kinetic_core::constants::DOCS_URL,
                sys_err.code()
            ),
            title: "Internal Server Error".to_string(),
            status: 500,
            detail: sys_err.user_message(),
            instance: None,
            code: sys_err.code().to_string(),
            retryable: sys_err.is_retryable(),
            details: serde_json::Value::Null,
            request_id: "".to_string(),
        }));
    }

    Ok(Json(serde_json::json!({ "success": true })))
}

/// Handles API requests to retrieve a reserved local zone file.
pub async fn handle_get_local_zone(
    Path(name): Path<String>,
) -> Result<Json<serde_json::Value>, crate::api::error::AppError> {
    let fqdn = kinetic_core::types::normalize_name(&name);

    if !kinetic_core::types::names::is_reserved_name(&fqdn) {
        return Err(crate::api::error::AppError::from(
            kinetic_core::error::RestApiError::BadRequest(
                "This endpoint is strictly for reserved local names (e.g. example.kin)."
                    .to_string(),
            ),
        ));
    }

    let apex = kinetic_core::types::names::extract_apex_name(&fqdn);
    let apex_no_tld = apex.trim_end_matches(kinetic_core::constants::NSP_SUFFIX);

    let path = kinetic_local::config::get_zones_dir()
        .join("local")
        .join(format!("{}.json", apex_no_tld));

    if let Ok(content) = std::fs::read_to_string(&path)
        && let Ok(zone) = serde_json::from_str::<serde_json::Value>(&content)
    {
        return Ok(Json(zone));
    }

    Err(crate::api::error::AppError::from(
        kinetic_core::error::RestApiError::NotFound,
    ))
}
