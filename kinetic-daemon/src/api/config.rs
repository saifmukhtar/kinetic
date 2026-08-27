//! HTTP REST API endpoints for daemon configuration, node status, owned names, and governance state.

use super::*;
use axum::{
    Json,
    extract::{Extension, State},
    http::StatusCode,
};

/// Handles requests to retrieve the current daemon configuration.
pub async fn handle_config(
    Extension(role): Extension<Role>,
    State(_state): State<ApiState>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    if !role.is_admin() {
        return Err(StatusCode::FORBIDDEN);
    }
    let config = kinetic_core::config::KineticConfig::load();
    Ok(Json(serde_json::json!({
        "status": "ok",
        "config": config
    })))
}

/// Handles requests to retrieve a list of names owned by this node.
pub async fn handle_owned_names(
    Extension(role): Extension<Role>,
    State(state): State<ApiState>,
) -> Result<Json<Vec<String>>, StatusCode> {
    if !role.can_publish() {
        return Err(StatusCode::FORBIDDEN);
    }
    let owned_key = kinetic_core::constants::DB_PREFIX_OWNED_NAMES;
    let owned_names: Vec<String> = match state.storage.get(owned_key) {
        Ok(Some(bytes)) => match serde_json::from_slice(&bytes) {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(error_code="KIN-IMPL-003", error=?e, "Corrupted data in Sled storage for owned_names key");
                Vec::new()
            }
        },
        _ => Vec::new(),
    };
    Ok(Json(owned_names))
}

/// Handles requests to retrieve the current network status (peer count, DHT size, uptime).
pub async fn handle_network_status(State(state): State<ApiState>) -> Json<serde_json::Value> {
    match state.network.get_network_status().await {
        Ok(status) => Json(status),
        Err(e) => Json(serde_json::json!({
            "status": format!("Error: {}", e),
            "peers": 0,
            "dht_size": 0,
            "uptime": "Unknown"
        })),
    }
}

/// Handles requests to retrieve the active governance state file.
pub async fn handle_get_governance() -> impl axum::response::IntoResponse {
    let gov = kinetic_core::governance::GLOBAL_GOVERNANCE_STATE
        .lock()
        .unwrap();
    let data = bincode::serialize(&*gov).unwrap_or_default();
    (axum::http::StatusCode::OK, data)
}

/// Handles requests to update the daemon configuration.
pub async fn handle_set_config(
    Extension(role): Extension<Role>,
    State(_state): State<ApiState>,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    if !role.is_admin() {
        return Err(StatusCode::FORBIDDEN);
    }
    
    if let Some(config_payload) = payload.get("config") {
        match serde_json::from_value::<kinetic_core::config::KineticConfig>(config_payload.clone()) {
            Ok(new_config) => {
                new_config.validate(); // Ensure no port collisions before saving
                let _ = new_config.save();
                Ok(Json(serde_json::json!({
                    "status": "ok", 
                    "message": "Configuration saved. Restart daemon to apply."
                })))
            }
            Err(e) => {
                Ok(Json(serde_json::json!({
                    "status": "error",
                    "message": format!("Invalid config payload format: {}", e)
                })))
            }
        }
    } else {
        Ok(Json(serde_json::json!({
            "status": "error",
            "message": "Missing 'config' object in payload."
        })))
    }
}

/// Handles requests to check the daemon health.
pub async fn handle_health(State(state): State<ApiState>) -> Json<serde_json::Value> {
    // Check if network channel is responsive
    let network_ok = state.network.get_network_status().await.is_ok();
    // Check if storage is accessible by reading a known key
    let storage_ok = state
        .storage
        .get(kinetic_core::constants::DB_PREFIX_LAST_DRAND)
        .is_ok();

    if network_ok && storage_ok {
        Json(serde_json::json!({
            "status": "OK",
            "network": "healthy",
            "storage": "healthy"
        }))
    } else {
        Json(serde_json::json!({
            "status": "ERROR",
            "network": if network_ok { "healthy" } else { "unresponsive" },
            "storage": if storage_ok { "healthy" } else { "unresponsive" }
        }))
    }
}

/// Handles requests to retrieve the local peer ID.
pub async fn handle_peer_id(State(state): State<ApiState>) -> impl axum::response::IntoResponse {
    match state.network.get_network_status().await {
        Ok(status) => {
            if let Some(peer_id) = status.get("peer_id").and_then(|p| p.as_str()) {
                (axum::http::StatusCode::OK, peer_id.to_string())
            } else {
                (
                    axum::http::StatusCode::SERVICE_UNAVAILABLE,
                    "Peer ID unknown (Node offline)".to_string(),
                )
            }
        }
        Err(_) => (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "Network channel closed".to_string(),
        ),
    }
}
