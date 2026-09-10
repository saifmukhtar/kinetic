//! HTTP REST API handlers for publishing Reveals, Commitments, Authorized KIDs, Manifests, and Action actions.

use super::*;
use axum::{
    Json,
    extract::{Extension, Path, State},
};
use kinetic_core::traits::KynProvider;
use kinetic_core::types::RevealExt;
use kinetic_core::types::clock::KynNetworkExt;
use kinetic_verify::signatures::VerifySignature;

/// Safely fetches the current Kyn using the network client, with verified local database cache fallback.
async fn get_safe_current_kyn(state: &ApiState) -> kinetic_core::types::Kyn {
    if let Ok(kyn) = state.network.get_current_kyn().await
        && kyn > 0
    {
        return kinetic_core::types::Kyn(kyn);
    }

    let kyn_provider =
        kinetic_network::client::drand::DrandProvider::new(Some(state.storage.clone()));
    match kyn_provider.load_cached_kyn() {
        Ok(kyn) if kyn.kyn > 0 => kinetic_core::types::Kyn(kyn.kyn),
        _ => kinetic_core::types::Kyn::now_local(),
    }
}

/// Handles API requests to publish a `Reveal` to the DHT.
///
/// # Errors
///
/// Returns an `AppError` if the name is invalid, the `Reveal` validation fails,
/// or if publishing to the DHT fails.
pub async fn handle_publish_record(
    axum::extract::Extension(role): axum::extract::Extension<Role>,
    State(state): State<ApiState>,
    Json(req): Json<PublishRequest>,
) -> Result<Json<PublishResponse>, crate::api::error::AppError> {
    if !role.can_nrs() {
        return Err(crate::api::error::AppError::from(
            kinetic_core::error::RestApiError::InsufficientPrivileges,
        ));
    }
    tracing::info!(
        "Received API publish request for name: {}",
        req.record.name()
    );

    // Normalize to canonical format
    let fqdn = kinetic_core::types::normalize_name(req.record.name());
    if let Err(e) = kinetic_core::types::is_valid_apex_name(&fqdn) {
        return Err(crate::api::error::AppError::from(
            kinetic_core::error::RestApiError::BadRequest(format!("Invalid name: {}", e)),
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
            return Err(crate::api::error::AppError::from(
                kinetic_core::error::RestApiError::BadRequest(format!("Invalid Reveal: {}", e)),
            ));
        }
        is_standard = true;
        kyn = reveal.kyn;
    }

    // Enforce drand staleness — reject Reveals whose VDF kyn is older
    // than RESQUARING_EPOCH_KYNS using the safe cached network Kyn.
    let current_kyn = get_safe_current_kyn(&state).await.0;

    if is_standard && current_kyn > 0 {
        if kyn > current_kyn {
            return Err(crate::api::error::AppError::from(
                kinetic_core::error::RestApiError::BadRequest(format!(
                    "Reveal rejected: VDF kyn {} is in the future (current kyn: {}).",
                    kyn, current_kyn
                )),
            ));
        }
        let age = current_kyn - kyn;
        if age > kinetic_core::types::RESQUARING_EPOCH_KYNS {
            return Err(crate::api::error::AppError::from(
                kinetic_core::error::RestApiError::BadRequest(format!(
                    "Reveal rejected: VDF kyn {} is {} kyns old (max allowed: {}). Please re-compute a fresh VDF proof.",
                    kyn, age, kinetic_core::types::RESQUARING_EPOCH_KYNS
                )),
            ));
        }
    }

    let payload_bytes = serde_json::to_vec(&name_record).map_err(|e| {
        kinetic_core::error::PublishError::Internal {
            message: format!("Serialization failed: {}", e),
            source: None,
        }
    })?;
    let payload_clone = payload_bytes.clone();

    state
        .network
        .publish_redundant_payload(&fqdn, payload_bytes)
        .await?;

    tracing::info!(
        "Successfully queued payload for {} to the DHT network",
        fqdn
    );

    let storage = state.storage.clone();
    let fqdn_persist = fqdn.clone();
    let name_record_clone = name_record.clone();

    tokio::task::spawn_blocking(move || {
        let owned_key = kinetic_core::constants::DB_PREFIX_OWNED_NAMES;
        let _lock = crate::api::OWNED_NAMES_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let mut owned = Vec::new();
        if let Ok(Some(bytes)) = storage.get(owned_key)
            && let Ok(names) = serde_json::from_slice::<Vec<String>>(&bytes)
        {
            owned = names;
        }
        if !owned.contains(&fqdn_persist) {
            owned.push(fqdn_persist.clone());
            if owned.len() > 10_000 {
                let skip_count = owned.len() - 10_000;
                owned = owned.into_iter().skip(skip_count).collect();
            }
            if let Ok(b) = serde_json::to_vec(&owned) {
                let _ = storage.put(owned_key, &b);
            }
        }
        drop(_lock);

        let reveal_key = format!("{}{}", kinetic_core::constants::DB_PREFIX_REVEAL, fqdn_persist);
        if let Ok(reveal_bytes) = serde_json::to_vec(&name_record_clone) {
            let _ = storage.put(reveal_key.as_bytes(), &reveal_bytes);
        }
    })
    .await
    .map_err(|e| kinetic_core::error::StorageError::WriteFailed(e.to_string()))?;

    tracing::info!(
        "Persisted {} to daemon storage for automatic Heartbeats",
        fqdn
    );

    // Spawn a background task to verify quorum threshold
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
) -> Result<Json<PublishResponse>, crate::api::error::AppError> {
    if !role.can_nrs() {
        return Err(crate::api::error::AppError::from(
            kinetic_core::error::RestApiError::InsufficientPrivileges,
        ));
    }
    tracing::info!("Received API commit request for name: {}", req.name);

    // Normalize to canonical format
    let fqdn = kinetic_core::types::normalize_name(&req.name);
    if let Err(e) = kinetic_core::types::is_valid_apex_name(&fqdn) {
        return Err(crate::api::error::AppError::from(
            kinetic_core::error::RestApiError::BadRequest(format!("Invalid name: {}", e)),
        ));
    }

    if req.commitment.hash == [0u8; 32] {
        return Err(crate::api::error::AppError::from(
            kinetic_core::error::RestApiError::BadRequest(
                "Commitment hash must not be all-zeros. Please provide a valid cryptographic commitment."
                    .to_string(),
            ),
        ));
    }

    let payload_bytes = serde_json::to_vec(&req.commitment).map_err(|e| {
        kinetic_core::error::PublishError::Internal {
            message: format!("Serialization failed: {}", e),
            source: None,
        }
    })?;

    state
        .network
        .publish_redundant_payload(&fqdn, payload_bytes.clone())
        .await?;

    tracing::info!(
        "Successfully queued Commitment for {} to the DHT network",
        fqdn
    );

    // Spawn a background task to verify quorum threshold
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

        if let Ok(content) = tokio::fs::read_to_string(&local_zone_file).await
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
            // This rescues users who lost their local record cache (.record.json) and the DHT dropped their record
            let reveal_key = format!("{}{}", kinetic_core::constants::DB_PREFIX_REVEAL, fqdn);
            let storage = state.storage.clone();
            let record_bytes = tokio::task::spawn_blocking(move || storage.get(reveal_key.as_bytes()))
                .await
                .map_err(|e| kinetic_core::error::ResolutionError::Internal {
                    message: format!("Storage worker task failed: {}", e),
                    source: None,
                })?
                .map_err(|e| kinetic_core::error::ResolutionError::Internal {
                    message: format!("Storage read failed: {}", e),
                    source: None,
                })?;

            match record_bytes {
                Some(bytes) => {
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
                None => {
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

/// Represents the result of a DHT quorum verification check.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct QuorumResponse {
    /// The fully qualified domain name.
    pub name: String,
    /// Number of distinct peers that confirmed storage.
    pub quorum_count: usize,
}

/// Handles requests to verify DHT quorum for a specific name record payload.
pub async fn handle_verify_quorum(
    State(state): State<ApiState>,
    Path(name): Path<String>,
    Json(record): Json<kinetic_core::types::NameRecord>,
) -> Result<Json<QuorumResponse>, crate::api::error::AppError> {
    let fqdn = kinetic_core::types::normalize_name(&name);
    kinetic_core::types::is_valid_apex_name(&fqdn)?;

    let payload = serde_json::to_vec(&record).map_err(|_| {
        crate::api::error::AppError::from(kinetic_core::error::RestApiError::BadRequest(
            "Invalid NameRecord payload".to_string(),
        ))
    })?;

    match state.network.verify_quorum(&fqdn, payload).await {
        Ok(count) => Ok(Json(QuorumResponse {
            name: fqdn,
            quorum_count: count,
        })),
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
    let statuses = tokio::task::spawn_blocking(|| {
        let local_dir = kinetic_local::config::get_zones_dir().join("local");
        let mut statuses = Vec::new();
        for r in kinetic_core::types::RESERVED_NAMES {
            let path = local_dir.join(format!("{}.json", r));
            statuses.push(ReservedNameStatus {
                name: r.to_string(),
                active: path.exists(),
            });
        }
        statuses
    })
    .await
    .map_err(|e| {
        crate::api::error::AppError::from(
            kinetic_core::error::SystemError::DiskPersistenceFailed(e.to_string()),
        )
    })?;

    Ok(Json(statuses))
}

/// Handles API requests to retrieve a local zone file for a given name.
///
/// # Errors
///
/// Returns an error if the zone file does not exist or has an invalid format.
pub async fn handle_get_zone(
    Path(name): Path<String>,
) -> Result<Json<kinetic_core::types::NrsZone>, crate::api::error::AppError> {
    let fqdn = kinetic_core::types::normalize_name(&name);
    kinetic_core::types::is_valid_apex_name(&fqdn)?;

    let path = kinetic_local::config::get_zones_dir().join("config").join(format!("{}.json", fqdn));
    match tokio::fs::read_to_string(&path).await {
        Ok(content) => match serde_json::from_str::<kinetic_core::types::NrsZone>(&content) {
            Ok(zone) => Ok(Json(zone)),
            Err(e) => Err(crate::api::error::AppError::from(
                kinetic_core::error::NrsError::ParseError(e),
            )),
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Err(crate::api::error::AppError::from(
                kinetic_core::error::RestApiError::NotFound,
            ))
        }
        Err(e) => Err(crate::api::error::AppError::from(
            kinetic_core::error::StorageError::ReadFailed(e.to_string()),
        )),
    }
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

    let zones_dir = kinetic_local::config::get_zones_dir().join("config");
    let path = zones_dir.join(format!("{}.json", fqdn));

    let content = serde_json::to_string_pretty(&zone).map_err(|e| {
        crate::api::error::AppError::from(kinetic_core::error::StorageError::WriteFailed(format!(
            "Serialization failed: {}",
            e
        )))
    })?;

    tokio::fs::create_dir_all(&zones_dir).await.map_err(|e| {
        crate::api::error::AppError::from(kinetic_core::error::StorageError::WriteFailed(
            format!("Failed to create zones directory: {}", e),
        ))
    })?;

    tokio::fs::write(&path, content).await.map_err(|e| {
        crate::api::error::AppError::from(kinetic_core::error::StorageError::WriteFailed(
            e.to_string(),
        ))
    })?;

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
) -> Result<Json<PublishResponse>, crate::api::error::AppError> {
    if !role.can_nrs() {
        return Err(crate::api::error::AppError::from(
            kinetic_core::error::RestApiError::InsufficientPrivileges,
        ));
    }
    let fqdn = kinetic_core::types::normalize_name(&name);
    kinetic_core::types::is_valid_apex_name(&fqdn)?;

    // 1. Read the current zone file asynchronously
    let zone_path = kinetic_local::config::get_zones_dir().join("config").join(format!("{}.json", fqdn));
    let content = match tokio::fs::read_to_string(&zone_path).await {
        Ok(c) => c,
        Err(_) => {
            return Err(crate::api::error::AppError::from(
                kinetic_core::error::RestApiError::NotFound,
            ));
        }
    };
    let zone: kinetic_core::types::NrsZone = serde_json::from_str(&content)
        .map_err(|e| crate::api::error::AppError::from(kinetic_core::error::NrsError::ParseError(e)))?;

    // 2. Load the persisted Reveal (stored at registration time)
    let reveal_key = format!("{}{}", kinetic_core::constants::DB_PREFIX_REVEAL, fqdn);
    let storage = state.storage.clone();
    let r_key = reveal_key.clone();
    let reveal_bytes = tokio::task::spawn_blocking(move || storage.get(r_key.as_bytes()))
        .await
        .map_err(|e| {
            crate::api::error::AppError::from(kinetic_core::error::StorageError::ReadFailed(
                format!("Storage worker task failed: {}", e),
            ))
        })?
        .map_err(|e| crate::api::error::AppError::from(e))?
        .ok_or_else(|| {
            crate::api::error::AppError::from(kinetic_core::error::RegistrationError::NotRegisteredLocal {
                name: fqdn.clone(),
            })
        })?;

    let mut record: kinetic_core::types::NameRecord = serde_json::from_slice(&reveal_bytes)
        .map_err(|_| {
            crate::api::error::AppError::from(kinetic_core::error::StorageError::DeserializationFailed(
                "Stored registration data is corrupted.".to_string(),
            ))
        })?;

    // 3. Load the daemon keypair and re-sign with the updated payload
    let identity_path = kinetic_local::config::get_base_dir().join("identity.key");
    let keypair = tokio::task::spawn_blocking(move || kinetic_local::identity::load_keypair(&identity_path))
        .await
        .map_err(|e| {
            crate::api::error::AppError::from(kinetic_core::error::IdentityError::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Identity worker task failed: {}", e)
            )))
        })?
        .map_err(|e| crate::api::error::AppError::from(e))?;

    let pubkey_bytes = keypair.pubkey_bytes();
    if record.pubkey() != pubkey_bytes.as_slice() {
        return Err(crate::api::error::AppError::from(
            kinetic_core::error::IdentityError::PubkeyMismatch(
                "The daemon key does not match the owner key for this name registration.".to_string(),
            ),
        ));
    }

    let payload = serde_json::to_vec(&zone).map_err(|e| {
        let err = kinetic_core::error::PublishError::ZoneSerializationFailed(e.to_string());
        tracing::error!(error_code = err.code(), "{}", err);
        crate::api::error::AppError::from(err)
    })?;

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
        let storage = state.storage.clone();
        let reveal_key_for_put = reveal_key.clone();
        tokio::task::spawn_blocking(move || {
            let _ = storage.put(reveal_key_for_put.as_bytes(), &updated_bytes);
        });
    }

    // 5. Serialize and publish to the DHT
    let dht_payload = serde_json::to_vec(&record).map_err(|e| {
        crate::api::error::AppError::from(kinetic_core::error::PublishError::Internal {
            message: format!("Serialization error: {}", e),
            source: None,
        })
    })?;

    state
        .network
        .publish_redundant_payload(&fqdn, dht_payload)
        .await
        .map_err(|e| crate::api::error::AppError::from(e))?;

    tracing::info!("Zone published to DHT for {}", fqdn);
    Ok(Json(PublishResponse {
        status: "success".to_string(),
        message: "Zone published to the Kinetic DHT network.".to_string(),
    }))
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
    tokio::fs::create_dir_all(&local_dir).await.map_err(|e| {
        crate::api::error::AppError::from(kinetic_core::error::StorageError::WriteFailed(
            format!("Failed to create local zones directory: {}", e),
        ))
    })?;
    let path = local_dir.join(format!("{}.json", apex_no_tld));

    let content = serde_json::to_string_pretty(&zone).map_err(|e| {
        crate::api::error::AppError::from(kinetic_core::error::StorageError::WriteFailed(format!(
            "Serialization failed: {}",
            e
        )))
    })?;

    tokio::fs::write(&path, content).await.map_err(|e| {
        crate::api::error::AppError::from(kinetic_core::error::StorageError::WriteFailed(
            e.to_string(),
        ))
    })?;

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

    match tokio::fs::remove_file(&path).await {
        Ok(_) => Ok(Json(serde_json::json!({ "success": true }))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Err(crate::api::error::AppError::from(
                kinetic_core::error::RestApiError::NotFound,
            ))
        }
        Err(e) => Err(crate::api::error::AppError::from(
            kinetic_core::error::StorageError::DeleteFailed(format!(
                "File delete failed: {}",
                e
            )),
        )),
    }
}

/// Handles API requests to retrieve a reserved local zone file.
pub async fn handle_get_local_zone(
    Path(name): Path<String>,
) -> Result<Json<kinetic_core::types::NrsZone>, crate::api::error::AppError> {
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

    match tokio::fs::read_to_string(&path).await {
        Ok(content) => match serde_json::from_str::<kinetic_core::types::NrsZone>(&content) {
            Ok(zone) => Ok(Json(zone)),
            Err(e) => Err(crate::api::error::AppError::from(
                kinetic_core::error::NrsError::ParseError(e),
            )),
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Err(crate::api::error::AppError::from(
                kinetic_core::error::RestApiError::NotFound,
            ))
        }
        Err(e) => Err(crate::api::error::AppError::from(
            kinetic_core::error::StorageError::ReadFailed(e.to_string()),
        )),
    }
}

/// Request payload for manually broadcasting a Fat NRS Zone update.


/// Request payload for manually broadcasting a Fat NRS Zone update.
#[derive(serde::Deserialize)]
pub struct FatZoneRequest {
    /// The private key of the delegated hot key, hex encoded.
    pub hot_key_hex: String,
    /// The master-key authorized delegation proof.
    pub authorized_manifest: kinetic_core::types::identity::AuthorizedManifest,
    /// The new DNS zone data.
    pub zone: kinetic_core::types::NrsZone,
}

/// Publishes a Fat NRS NameRecord (Zone Update) using a delegated hot key.
pub async fn handle_publish_fat_zone(
    axum::extract::Extension(role): axum::extract::Extension<crate::api::Role>,
    axum::extract::State(state): axum::extract::State<crate::api::ApiState>,
    axum::extract::Path(name): axum::extract::Path<String>,
    axum::Json(req): axum::Json<FatZoneRequest>,
) -> Result<axum::Json<crate::api::nrs::PublishResponse>, crate::api::error::AppError> {
    if !role.can_nrs() {
        return Err(crate::api::error::AppError::from(
            kinetic_core::error::RestApiError::InsufficientPrivileges,
        ));
    }
    
    let fqdn = kinetic_core::types::names::normalize_name(&name);
    kinetic_core::types::names::is_valid_apex_name(&fqdn)?;

    // 1. Verify the capability is present in the manifest
    let has_cap = req.authorized_manifest.manifest.services.iter()
        .any(|s| s.service_type == "kinetic.capability.dns_update");
    if !has_cap {
        return Err(crate::api::error::AppError::from(
            kinetic_core::error::RestApiError::BadRequest("Provided AuthorizedManifest does not contain kinetic.capability.dns_update capability.".to_string()),
        ));
    }

    // 2. Load the hot key
    let hot_key_bytes = hex::decode(&req.hot_key_hex).map_err(|e| {
        crate::api::error::AppError::from(kinetic_core::error::RestApiError::BadRequest(format!("Invalid hot_key_hex: {}", e)))
    })?;
    let keypair = kinetic_primitives::keys::KineticKeypair::from_slice(&hot_key_bytes).map_err(|e| {
         crate::api::error::AppError::from(kinetic_core::error::RestApiError::BadRequest(format!("Invalid ML-DSA keypair: {}", e)))
    })?;

    // 3. Load the persisted Reveal (stored at registration time) to retain the valid VDF proof
    let reveal_key = format!("{}{}", kinetic_core::constants::DB_PREFIX_REVEAL, fqdn);
    let storage = state.storage.clone();
    let r_key = reveal_key.clone();
    let reveal_bytes = tokio::task::spawn_blocking(move || storage.get(r_key.as_bytes()))
        .await
        .map_err(|e| {
            crate::api::error::AppError::from(kinetic_core::error::StorageError::ReadFailed(
                format!("Storage worker task failed: {}", e),
            ))
        })?
        .map_err(|e| crate::api::error::AppError::from(e))?
        .ok_or_else(|| {
            crate::api::error::AppError::from(kinetic_core::error::RegistrationError::NotRegisteredLocal {
                name: fqdn.clone(),
            })
        })?;

    let mut record: kinetic_core::types::NameRecord = serde_json::from_slice(&reveal_bytes)
        .map_err(|_| {
            crate::api::error::AppError::from(kinetic_core::error::StorageError::DeserializationFailed(
                "Stored registration data is corrupted.".to_string(),
            ))
        })?;

    // 4. Update payload and authorization, then sign with hot key
    let payload_bytes = serde_json::to_vec(&req.zone).map_err(|e| {
        let err = kinetic_core::error::PublishError::ZoneSerializationFailed(e.to_string());
        tracing::error!(error_code = err.code(), "{}", err);
        crate::api::error::AppError::from(err)
    })?;

    match &mut record {
        kinetic_core::types::NameRecord::Standard(reveal) => {
            reveal.payload = payload_bytes;
            reveal.authorization = Some(Box::new(req.authorized_manifest));
            let signable = reveal.signable_bytes(kinetic_core::constants::NETWORK_SALT);
            reveal.signature = tokio::task::spawn_blocking(move || keypair.sign(&signable)).await.unwrap();
        }
        kinetic_core::types::NameRecord::Prime { name, payload, authorization, signature, .. }
        | kinetic_core::types::NameRecord::Infra { name, payload, authorization, signature, .. } => {
            *payload = payload_bytes;
            *authorization = Some(Box::new(req.authorized_manifest));
            
            let mut signable = Vec::new();
            signable.extend_from_slice(&(name.len() as u32).to_be_bytes());
            signable.extend_from_slice(name.as_bytes());
            signable.extend_from_slice(&(payload.len() as u32).to_be_bytes());
            signable.extend_from_slice(payload);
            signable.extend_from_slice(kinetic_core::constants::NETWORK_SALT);
            
            *signature = tokio::task::spawn_blocking(move || keypair.sign(&signable)).await.unwrap();
        }
    }

    // 5. Save the updated reveal locally so the daemon serves the newest zone on fallback
    let final_bytes = serde_json::to_vec(&record).unwrap();
    let network = state.network.clone();
    
    let s2 = state.storage.clone();
    let fqdn2 = fqdn.clone();
    let fb = final_bytes.clone();
    tokio::task::spawn_blocking(move || {
        let _ = s2.put(reveal_key.as_bytes(), &fb);
    });

    network.publish_redundant_payload(&fqdn2, final_bytes)
        .await
        .map_err(|e| crate::api::error::AppError::from(e))?;

    Ok(axum::Json(crate::api::nrs::PublishResponse {
        status: "success".to_string(),
        message: format!("Fat Zone payload successfully broadcast for {}", fqdn),
    }))
}
