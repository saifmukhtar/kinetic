//! HTTP REST API handlers for resolving .kin names and Kinetic Identifiers (KIDs).

use super::*;
use axum::{
    Json,
    extract::{Path, State},
};
use kinetic_verify::signatures::VerifySignature;

use tracing::info;

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
        let local_zone_file = kinetic_core::config::get_zones_dir()
            .join("local")
            .join(format!("{}.json", apex_no_tld));

        if let Ok(content) = std::fs::read_to_string(&local_zone_file) {
            if let Ok(zone) = serde_json::from_str::<kinetic_core::types::NrsZone>(&content) {
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
                let err = kinetic_core::error::ResolutionError::SignatureVerificationFailed(e.to_string());
                tracing::warn!(
                    error_code = err.code(),
                    "{}", err
                );
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
            tracing::warn!(
                error_code = e.code(),
                "Resolution error: {}",
                e.to_string()
            );
            return Err(e.into());
        }
    };

    Ok(Json(record))
}

/// Handles API requests to resolve a Kinetic Identifier (KID) and its associated manifest.
///
/// # Errors
///
/// Returns an error if the KID cannot be found in the DHT, or if the retrieved payload is invalid.
pub async fn handle_resolve_kid(
    State(state): State<ApiState>,
    Path(did): Path<String>,
) -> Result<Json<serde_json::Value>, crate::api::error::AppError> {
    info!("Resolving KID via API: {}", did);

    // Resolve KID - Notice how this entire massive match block is now just a single `?`
    let kid_payload = state.network.resolve_redundant_payload(&did).await?;

    let kid_doc: kinetic_kid::Document =
        match serde_json::from_slice::<kinetic_core::types::AuthorizedKid>(&kid_payload) {
            Ok(auth) => auth.kid_doc,
            Err(_) => {
                // Fallback for older raw documents
                serde_json::from_slice(&kid_payload).map_err(|_| {
                    kinetic_core::error::ResolutionError::Internal {
                        message: "Invalid KID data payload".to_string(),
                        source: None,
                    }
                })?
            }
        };

    // Try to resolve Manifest
    let manifest_key = hex::encode(kinetic_primitives::sha256_hash(
        format!("{}#manifest", did).as_bytes(),
    ));

    let mut res = serde_json::json!({
        "kid_document": kid_doc,
    });

    if let Ok(man_payload) = state.network.resolve_redundant_payload(&manifest_key).await {
        let manifest_opt =
            match serde_json::from_slice::<kinetic_core::types::AuthorizedManifest>(&man_payload) {
                Ok(auth) => Some(auth.manifest),
                Err(_) => serde_json::from_slice::<kinetic_kid::Manifest>(&man_payload).ok(),
            };

        if let Some(manifest) = manifest_opt
            && let Ok(val) = serde_json::to_value(manifest)
        {
            res["manifest_document"] = val;
        }
    }

    Ok(Json(res))
}
