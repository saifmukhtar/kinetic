//! HTTP REST API handlers for resolving .kin names and Kinetic Identifiers (KIDs).

use super::*;
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use kinetic_verify::signatures::VerifySignature;

use tracing::info;

/// Handles API requests to resolve a Kinetic name.
/// Searches the DHT and falls back to a local daemon backup if the name cannot be found on the network.
///
/// # Errors
///
/// Returns a tuple containing a `StatusCode` and an error JSON payload if the name is not found
/// or if resolution fails due to network offline states or data corruption.
pub async fn handle_resolve_name(
    State(state): State<ApiState>,
    Path(name): Path<String>,
) -> Result<Json<kinetic_core::types::NameRecord>, (StatusCode, Json<serde_json::Value>)> {
    let fqdn = kinetic_core::types::normalize_name(&name);

    match state.network.resolve_redundant_payload(&fqdn).await {
        Ok(payload) => match serde_json::from_slice::<kinetic_core::types::NameRecord>(&payload) {
            Ok(record) => {
                let dev_mode = kinetic_core::config::is_dev_mode();
                if !dev_mode {
                    if let Err(e) = record.verify_signature(kinetic_core::constants::NETWORK_SALT) {
                        tracing::warn!("Rejecting spoofed NameRecord from network (CDN cache poisoning): {:?}", e);
                        return Err((
                            StatusCode::FORBIDDEN,
                            Json(serde_json::json!({"error": "NameRecord cryptographic signature verification failed. The record is spoofed or corrupted."})),
                        ));
                    }
                }
                Ok(Json(record))
            }
            Err(_) => Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Invalid NameRecord payload on DHT"})),
            )),
        },
        Err(kinetic_core::error::ResolutionError::NotFound { .. }) => {
            // Fallback to local storage if DHT lookup fails or returns nothing
            // This rescues users who lost their local reveal.json and the DHT dropped their record
            let reveal_key = format!("{}{}", kinetic_core::constants::DB_PREFIX_REVEAL, fqdn);
            match state.storage.get(reveal_key.as_bytes()) {
                Ok(Some(bytes)) => {
                    match serde_json::from_slice::<kinetic_core::types::NameRecord>(&bytes) {
                        Ok(record) => {
                            tracing::info!("Recovered {} from local daemon storage backup!", fqdn);
                            Ok(Json(record))
                        }
                        Err(_) => Err((
                            StatusCode::NOT_FOUND,
                            Json(
                                serde_json::json!({"error": format!("Name {} not found on DHT and local backup corrupted", fqdn)}),
                            ),
                        )),
                    }
                }
                _ => Err((
                    StatusCode::NOT_FOUND,
                    Json(
                        serde_json::json!({"error": format!("Name {} not found on DHT or local daemon cache", fqdn)}),
                    ),
                )),
            }
        }
        Err(kinetic_core::error::ResolutionError::Offline) => {
            let api_err =
                kinetic_core::ApiError::from(kinetic_core::error::ResolutionError::Offline);
            Err((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::to_value(api_err).unwrap_or_default()),
            ))
        }
        Err(e) => {
            let api_err = kinetic_core::ApiError::from(e);
            tracing::warn!(
                error_code = api_err.code,
                "Resolution error: {}",
                api_err.detail
            );
            Err((
                StatusCode::from_u16(api_err.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                Json(serde_json::to_value(api_err).unwrap_or_default()),
            ))
        }
    }
}

/// Handles API requests to resolve a Kinetic Identifier (KID) and its associated manifest.
///
/// # Errors
///
/// Returns an error if the KID cannot be found in the DHT, or if the retrieved payload is invalid.
pub async fn handle_resolve_kid(
    State(state): State<ApiState>,
    Path(did): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    info!("Resolving KID via API: {}", did);

    // Resolve KID
    let kid_payload = match state.network.resolve_redundant_payload(&did).await {
        Ok(p) => p,
        Err(e) => {
            let status = match &e {
                kinetic_core::error::ResolutionError::NotFound { .. } => StatusCode::NOT_FOUND,
                kinetic_core::error::ResolutionError::Offline => StatusCode::SERVICE_UNAVAILABLE,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };
            return Err((status, format!("DHT error: {}", e)));
        }
    };

    let kid_doc: kinetic_kid::KidDocument =
        match serde_json::from_slice::<kinetic_core::types::AuthorizedKid>(&kid_payload) {
            Ok(auth) => auth.kid_doc,
            Err(_) => {
                // Fallback for older raw documents
                serde_json::from_slice(&kid_payload).map_err(|_| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Invalid KID data".to_string(),
                    )
                })?
            }
        };

    // Try to resolve Manifest
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(format!("{}#manifest", did).as_bytes());
    let manifest_key = hex::encode(hasher.finalize());

    let mut response = serde_json::json!({
        "kid_document": kid_doc,
    });

    if let Ok(man_payload) = state.network.resolve_redundant_payload(&manifest_key).await {
        let manifest_opt =
            match serde_json::from_slice::<kinetic_core::types::AuthorizedManifest>(&man_payload) {
                Ok(auth) => Some(auth.manifest),
                Err(_) => {
                    serde_json::from_slice::<kinetic_kid::CapabilityManifest>(&man_payload).ok()
                }
            };

        if let Some(manifest) = manifest_opt
            && let Ok(val) = serde_json::to_value(manifest)
        {
            response["manifest_document"] = val;
        }
    }

    Ok(Json(response))
}
