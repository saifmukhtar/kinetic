use super::*;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};

/// Handles API requests to retrieve a local zone file for a given name.
///
/// # Errors
///
/// Returns an error if the zone file does not exist or has an invalid format.
pub async fn handle_get_zone(
    Path(name): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let fqdn = kinetic_core::types::normalize_name(&name);
    let path = kinetic_core::config::get_zones_dir().join(format!("{}.json", fqdn));
    if let Ok(content) = std::fs::read_to_string(path) {
        match serde_json::from_str::<serde_json::Value>(&content) {
            Ok(zone) => return Ok(Json(zone)),
            Err(e) => {
                return Err((
                    StatusCode::UNPROCESSABLE_ENTITY,
                    Json(
                        serde_json::json!({ "error": format!("Invalid zone file format: {}", e) }),
                    ),
                ))
            }
        }
    }
    Err((
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({ "error": "Zone not found" })),
    ))
}

/// Handles API requests to save changes to a local zone file without broadcasting to the network.
///
/// # Errors
///
/// Returns an error if serialization fails or if the daemon lacks filesystem write permissions.
pub async fn handle_post_zone(
    Path(name): Path<String>,
    Json(zone): Json<kinetic_core::types::DnsZone>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let fqdn = kinetic_core::types::normalize_name(&name);
    let path = kinetic_core::config::get_zones_dir().join(format!("{}.json", fqdn));
    let _ = std::fs::create_dir_all(kinetic_core::config::get_zones_dir());

    let content = match serde_json::to_string_pretty(&zone) {
        Ok(c) => c,
        Err(e) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": format!("Serialization failed: {}", e) })),
            ))
        }
    };
    if let Err(e) = std::fs::write(&path, content) {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": format!("File write failed: {}", e) })),
        ));
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
    State(state): State<ApiState>,
    Path(name): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let fqdn = kinetic_core::types::normalize_name(&name);

    // 1. Read the current zone file
    let zone_path = kinetic_core::config::get_zones_dir().join(format!("{}.json", fqdn));
    let content = match std::fs::read_to_string(&zone_path) {
        Ok(c) => c,
        Err(_) => {
            return Err((
                StatusCode::NOT_FOUND,
                Json(
                    serde_json::json!({ "error": "Zone file not found. Save your zone first via POST /zone/{name}." }),
                ),
            ))
        }
    };
    let zone: kinetic_core::types::DnsZone = match serde_json::from_str(&content) {
        Ok(z) => z,
        Err(_) => {
            return Err((
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(serde_json::json!({ "error": "Invalid zone file format" })),
            ))
        }
    };

    // 2. Load the persisted Reveal (stored at registration time)
    let reveal_key = format!("kinetic_reveal:{}", fqdn);
    let reveal_bytes = match state.storage.get(reveal_key.as_bytes()) {
        Ok(Some(b)) => b,
        _ => {
            return Err((
                StatusCode::NOT_FOUND,
                Json(
                    serde_json::json!({ "error": "No registration record found for this name. Register the name first." }),
                ),
            ))
        }
    };
    let mut reveal: kinetic_core::types::Reveal = match serde_json::from_slice(&reveal_bytes) {
        Ok(r) => r,
        Err(_) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "Stored registration data is corrupted." })),
            ))
        }
    };

    // 3. Load the daemon keypair and re-sign with the updated payload
    let identity_path = kinetic_core::config::get_base_dir().join("identity.key");
    let keypair = match kinetic_core::types::load_keypair(&identity_path.to_string_lossy()) {
        Ok(k) => k,
        Err(_) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "Could not load identity keypair." })),
            ))
        }
    };

    reveal.payload = match serde_json::to_vec(&zone) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error_code="KIN-VDF-002", error=?e, "Failed to serialize zone payload — cannot publish");
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "[KIN-VDF-002] Failed to serialize zone data" })),
            ));
        }
    };

    let signable = reveal.signable_bytes();
    use ed25519_dalek::Signer;
    reveal.signature = keypair.sign(&signable).to_bytes().to_vec();

    // 4. Update the stored Reveal so future zone publishes reflect the latest payload
    if let Ok(updated_bytes) = serde_json::to_vec(&reveal) {
        let _ = state.storage.put(reveal_key.as_bytes(), &updated_bytes);
    }

    // 5. Serialize and publish to the DHT
    let dht_payload = match serde_json::to_vec(&reveal) {
        Ok(b) => b,
        Err(e) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": format!("Serialization error: {}", e) })),
            ))
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
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(
                serde_json::json!({ "error": format!("DHT publish failed: {}", e.user_message()) }),
            ),
        )),
    }
}
