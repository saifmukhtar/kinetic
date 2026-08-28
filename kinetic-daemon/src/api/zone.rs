//! HTTP REST API handlers for managing local NRS zone files and re-signing/publishing updated records to the DHT.

use super::*;
use axum::{
    Json,
    extract::{Extension, Path, State},
};

/// Represents the status of a reserved name in the local network configuration.
#[derive(serde::Serialize)]
pub struct ReservedNameStatus {
    /// The reserved name (e.g., "example", "localhost").
    pub name: String,
    /// True if a local zone override file exists for this name.
    pub active: bool,
}

/// Handles API requests to get the list of reserved names and their active local status.
pub async fn handle_get_reserved_names() -> Result<Json<Vec<ReservedNameStatus>>, crate::api::error::AppError> {
    let local_dir = kinetic_core::config::get_zones_dir().join("local");

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
    
    let path = kinetic_core::config::get_zones_dir().join(format!("{}.json", fqdn));
    if let Ok(content) = std::fs::read_to_string(path) {
        match serde_json::from_str::<serde_json::Value>(&content) {
            Ok(zone) => return Ok(Json(zone)),
            Err(e) => {
                return Err(crate::api::error::AppError(kinetic_core::ApiError {
                    error_type: format!("{}/errors/KIN-API-422", kinetic_core::constants::DOCS_URL),
                    title: "Unprocessable Entity".to_string(),
                    status: 422,
                    detail: format!("Invalid zone file format: {}", e),
                    instance: None,
                    code: "KIN-API-422".to_string(),
                    retryable: false,
                    details: serde_json::Value::Null,
                    request_id: "".to_string(),
                }));
            }
        }
    }
    Err(crate::api::error::AppError(kinetic_core::ApiError {
        error_type: format!("{}/errors/KIN-API-404", kinetic_core::constants::DOCS_URL),
        title: "Not Found".to_string(),
        status: 404,
        detail: "Zone not found".to_string(),
        instance: None,
        code: "KIN-API-404".to_string(),
        retryable: false,
        details: serde_json::Value::Null,
        request_id: "".to_string(),
    }))
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
    if !role.can_publish() {
        return Err(crate::api::error::AppError(kinetic_core::ApiError {
            error_type: format!("{}/errors/KIN-API-001", kinetic_core::constants::DOCS_URL),
            title: "Unauthorized".to_string(),
            status: 403,
            detail: "Insufficient privileges: Requires Publish or Admin role".to_string(),
            instance: None,
            code: "KIN-API-001".to_string(),
            retryable: false,
            details: serde_json::Value::Null,
            request_id: "".to_string(),
        }));
    }
    let fqdn = kinetic_core::types::normalize_name(&name);
    kinetic_core::types::is_valid_apex_name(&fqdn)?;
    
    let path = kinetic_core::config::get_zones_dir().join(format!("{}.json", fqdn));
    let _ = std::fs::create_dir_all(kinetic_core::config::get_zones_dir());

    let content = match serde_json::to_string_pretty(&zone) {
        Ok(c) => c,
        Err(e) => {
            return Err(crate::api::error::AppError(kinetic_core::ApiError {
                error_type: format!("{}/errors/KIN-API-500", kinetic_core::constants::DOCS_URL),
                title: "Internal Server Error".to_string(),
                status: 500,
                detail: format!("Serialization failed: {}", e),
                instance: None,
                code: "KIN-API-500".to_string(),
                retryable: false,
                details: serde_json::Value::Null,
                request_id: "".to_string(),
            }));
        }
    };
    if let Err(e) = std::fs::write(&path, content) {
        return Err(crate::api::error::AppError(kinetic_core::ApiError {
            error_type: format!("{}/errors/KIN-API-500", kinetic_core::constants::DOCS_URL),
            title: "Internal Server Error".to_string(),
            status: 500,
            detail: format!("File write failed: {}", e),
            instance: None,
            code: "KIN-API-500".to_string(),
            retryable: false,
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
    if !role.can_publish() {
        return Err(crate::api::error::AppError(kinetic_core::ApiError {
            error_type: format!("{}/errors/KIN-API-001", kinetic_core::constants::DOCS_URL),
            title: "Unauthorized".to_string(),
            status: 403,
            detail: "Insufficient privileges: Requires Publish or Admin role".to_string(),
            instance: None,
            code: "KIN-API-001".to_string(),
            retryable: false,
            details: serde_json::Value::Null,
            request_id: "".to_string(),
        }));
    }
    let fqdn = kinetic_core::types::normalize_name(&name);
    kinetic_core::types::is_valid_apex_name(&fqdn)?;

    // 1. Read the current zone file
    let zone_path = kinetic_core::config::get_zones_dir().join(format!("{}.json", fqdn));
    let content = match std::fs::read_to_string(&zone_path) {
        Ok(c) => c,
        Err(_) => {
            return Err(crate::api::error::AppError(kinetic_core::ApiError {
                error_type: format!("{}/errors/KIN-API-404", kinetic_core::constants::DOCS_URL),
                title: "Not Found".to_string(),
                status: 404,
                detail: "Zone file not found. Save your zone first via POST /zone/{name}.".to_string(),
                instance: None,
                code: "KIN-API-404".to_string(),
                retryable: false,
                details: serde_json::Value::Null,
                request_id: "".to_string(),
            }));
        }
    };
    let zone: kinetic_core::types::NrsZone = match serde_json::from_str(&content) {
        Ok(z) => z,
        Err(_) => {
            return Err(crate::api::error::AppError(kinetic_core::ApiError {
                error_type: format!("{}/errors/KIN-API-422", kinetic_core::constants::DOCS_URL),
                title: "Unprocessable Entity".to_string(),
                status: 422,
                detail: "Invalid zone file format".to_string(),
                instance: None,
                code: "KIN-API-422".to_string(),
                retryable: false,
                details: serde_json::Value::Null,
                request_id: "".to_string(),
            }));
        }
    };

    // 2. Load the persisted Reveal (stored at registration time)
    let reveal_key = format!("{}{}", kinetic_core::constants::DB_PREFIX_REVEAL, fqdn);
    let reveal_bytes = match state.storage.get(reveal_key.as_bytes()) {
        Ok(Some(b)) => b,
        _ => {
            return Err(crate::api::error::AppError(kinetic_core::ApiError {
                error_type: format!("{}/errors/KIN-API-404", kinetic_core::constants::DOCS_URL),
                title: "Not Found".to_string(),
                status: 404,
                detail: "No registration record found for this name. Register the name first.".to_string(),
                instance: None,
                code: "KIN-API-404".to_string(),
                retryable: false,
                details: serde_json::Value::Null,
                request_id: "".to_string(),
            }));
        }
    };
    let mut record: kinetic_core::types::NameRecord = match serde_json::from_slice(&reveal_bytes) {
        Ok(r) => r,
        Err(_) => {
            return Err(crate::api::error::AppError(kinetic_core::ApiError {
                error_type: format!("{}/errors/KIN-API-500", kinetic_core::constants::DOCS_URL),
                title: "Internal Server Error".to_string(),
                status: 500,
                detail: "Stored registration data is corrupted.".to_string(),
                instance: None,
                code: "KIN-API-500".to_string(),
                retryable: false,
                details: serde_json::Value::Null,
                request_id: "".to_string(),
            }));
        }
    };

    // 3. Load the daemon keypair and re-sign with the updated payload
    let identity_path = kinetic_core::config::get_base_dir().join("identity.key");
    let keypair = match kinetic_core::types::load_keypair(&identity_path) {
        Ok(k) => k,
        Err(_) => {
            return Err(crate::api::error::AppError(kinetic_core::ApiError {
                error_type: format!("{}/errors/KIN-API-500", kinetic_core::constants::DOCS_URL),
                title: "Internal Server Error".to_string(),
                status: 500,
                detail: "Could not load identity keypair.".to_string(),
                instance: None,
                code: "KIN-API-500".to_string(),
                retryable: false,
                details: serde_json::Value::Null,
                request_id: "".to_string(),
            }));
        }
    };

    let pubkey_bytes = keypair.pubkey_bytes();
    if record.pubkey() != pubkey_bytes.as_slice() {
        return Err(crate::api::error::AppError(kinetic_core::ApiError {
            error_type: format!("{}/errors/KIN-API-409", kinetic_core::constants::DOCS_URL),
            title: "Conflict".to_string(),
            status: 409,
            detail: "Identity key mismatch with name registration".to_string(),
            instance: None,
            code: "KIN-API-409".to_string(),
            retryable: false,
            details: serde_json::Value::Null,
            request_id: "".to_string(),
        }));
    }

    let payload = match serde_json::to_vec(&zone) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error_code="KIN-PUB-015", error=?e, "Failed to serialize zone payload — cannot publish");
            return Err(kinetic_core::error::PublishError::Internal {
                message: "[KIN-PUB-015] Failed to serialize zone data".to_string(),
                source: None,
            }.into());
        }
    };

    match &mut record {
        kinetic_core::types::NameRecord::Standard(r) => {
            r.payload = payload;
            let signable = r.signable_bytes(kinetic_core::constants::NETWORK_SALT);
            r.signature = keypair.sign(&signable);
        }
        kinetic_core::types::NameRecord::Prime { name, payload: p, signature: s, .. }
        | kinetic_core::types::NameRecord::Infra { name, payload: p, signature: s, .. } => {
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
            }.into());
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
    if !role.can_publish() {
        return Err(crate::api::error::AppError(kinetic_core::ApiError {
            error_type: format!("{}/errors/KIN-API-001", kinetic_core::constants::DOCS_URL),
            title: "Unauthorized".to_string(),
            status: 403,
            detail: "Insufficient privileges: Requires Publish or Admin role".to_string(),
            instance: None,
            code: "KIN-API-001".to_string(),
            retryable: false,
            details: serde_json::Value::Null,
            request_id: "".to_string(),
        }));
    }

    let fqdn = kinetic_core::types::normalize_name(&name);
    if !kinetic_core::types::names::is_reserved_name(&fqdn) {
        return Err(crate::api::error::AppError(kinetic_core::ApiError {
            error_type: format!("{}/errors/KIN-API-400", kinetic_core::constants::DOCS_URL),
            title: "Bad Request".to_string(),
            status: 400,
            detail: "This endpoint is strictly for reserved local names (e.g. example.kin).".to_string(),
            instance: None,
            code: "KIN-API-400".to_string(),
            retryable: false,
            details: serde_json::Value::Null,
            request_id: "".to_string(),
        }));
    }

    let apex = kinetic_core::types::names::extract_apex_name(&fqdn);
    let apex_no_tld = apex.trim_end_matches(kinetic_core::constants::NSP_SUFFIX);

    let local_dir = kinetic_core::config::get_zones_dir().join("local");
    let _ = std::fs::create_dir_all(&local_dir);
    let path = local_dir.join(format!("{}.json", apex_no_tld));

    let content = match serde_json::to_string_pretty(&zone) {
        Ok(c) => c,
        Err(e) => {
            return Err(crate::api::error::AppError(kinetic_core::ApiError {
                error_type: format!("{}/errors/KIN-API-500", kinetic_core::constants::DOCS_URL),
                title: "Internal Server Error".to_string(),
                status: 500,
                detail: format!("Serialization failed: {}", e),
                instance: None,
                code: "KIN-API-500".to_string(),
                retryable: false,
                details: serde_json::Value::Null,
                request_id: "".to_string(),
            }));
        }
    };

    if let Err(e) = std::fs::write(&path, content) {
        return Err(crate::api::error::AppError(kinetic_core::ApiError {
            error_type: format!("{}/errors/KIN-API-500", kinetic_core::constants::DOCS_URL),
            title: "Internal Server Error".to_string(),
            status: 500,
            detail: format!("File write failed: {}", e),
            instance: None,
            code: "KIN-API-500".to_string(),
            retryable: false,
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
    if !role.can_publish() {
        return Err(crate::api::error::AppError(kinetic_core::ApiError {
            error_type: format!("{}/errors/KIN-API-001", kinetic_core::constants::DOCS_URL),
            title: "Unauthorized".to_string(),
            status: 403,
            detail: "Insufficient privileges: Requires Publish or Admin role".to_string(),
            instance: None,
            code: "KIN-API-001".to_string(),
            retryable: false,
            details: serde_json::Value::Null,
            request_id: "".to_string(),
        }));
    }

    let fqdn = kinetic_core::types::normalize_name(&name);
    if !kinetic_core::types::names::is_reserved_name(&fqdn) {
        return Err(crate::api::error::AppError(kinetic_core::ApiError {
            error_type: format!("{}/errors/KIN-API-400", kinetic_core::constants::DOCS_URL),
            title: "Bad Request".to_string(),
            status: 400,
            detail: "This endpoint is strictly for reserved local names (e.g. example.kin).".to_string(),
            instance: None,
            code: "KIN-API-400".to_string(),
            retryable: false,
            details: serde_json::Value::Null,
            request_id: "".to_string(),
        }));
    }

    let apex = kinetic_core::types::names::extract_apex_name(&fqdn);
    let apex_no_tld = apex.trim_end_matches(kinetic_core::constants::NSP_SUFFIX);

    let path = kinetic_core::config::get_zones_dir()
        .join("local")
        .join(format!("{}.json", apex_no_tld));

    if path.exists() {
        if let Err(e) = std::fs::remove_file(&path) {
            return Err(crate::api::error::AppError(kinetic_core::ApiError {
                error_type: format!("{}/errors/KIN-API-500", kinetic_core::constants::DOCS_URL),
                title: "Internal Server Error".to_string(),
                status: 500,
                detail: format!("File delete failed: {}", e),
                instance: None,
                code: "KIN-API-500".to_string(),
                retryable: false,
                details: serde_json::Value::Null,
                request_id: "".to_string(),
            }));
        }
    }

    Ok(Json(serde_json::json!({ "success": true })))
}

/// Handles API requests to retrieve a reserved local zone file.
pub async fn handle_get_local_zone(
    Path(name): Path<String>,
) -> Result<Json<serde_json::Value>, crate::api::error::AppError> {
    let fqdn = kinetic_core::types::normalize_name(&name);

    if !kinetic_core::types::names::is_reserved_name(&fqdn) {
        return Err(crate::api::error::AppError(kinetic_core::ApiError {
            error_type: format!("{}/errors/KIN-API-400", kinetic_core::constants::DOCS_URL),
            title: "Bad Request".to_string(),
            status: 400,
            detail: "This endpoint is strictly for reserved local names (e.g. example.kin).".to_string(),
            instance: None,
            code: "KIN-API-400".to_string(),
            retryable: false,
            details: serde_json::Value::Null,
            request_id: "".to_string(),
        }));
    }

    let apex = kinetic_core::types::names::extract_apex_name(&fqdn);
    let apex_no_tld = apex.trim_end_matches(kinetic_core::constants::NSP_SUFFIX);

    let path = kinetic_core::config::get_zones_dir()
        .join("local")
        .join(format!("{}.json", apex_no_tld));

    if let Ok(content) = std::fs::read_to_string(&path) {
        if let Ok(zone) = serde_json::from_str::<serde_json::Value>(&content) {
            return Ok(Json(zone));
        }
    }

    Err(crate::api::error::AppError(kinetic_core::ApiError {
        error_type: format!("{}/errors/KIN-API-404", kinetic_core::constants::DOCS_URL),
        title: "Not Found".to_string(),
        status: 404,
        detail: "Local zone override not found".to_string(),
        instance: None,
        code: "KIN-API-404".to_string(),
        retryable: false,
        details: serde_json::Value::Null,
        request_id: "".to_string(),
    }))
}
