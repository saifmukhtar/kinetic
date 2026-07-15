use super::*;
use axum::{extract::State, Json};

/// Handles requests to retrieve the current daemon configuration.
pub async fn handle_config(State(state): State<ApiState>) -> Json<serde_json::Value> {
    let config = kinetic_core::config::KineticConfig::load();
    Json(serde_json::json!({
        "token": state.auth_token,
        "mode": config.daemon.network_mode
    }))
}

/// Handles requests to retrieve a list of names owned by this node.
pub async fn handle_owned_names(State(state): State<ApiState>) -> Json<Vec<String>> {
    let owned_key = b"kinetic_owned_names";
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
    Json(owned_names)
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

/// Handles requests to update the daemon configuration, such as changing the network mode.
pub async fn handle_set_config(
    State(_state): State<ApiState>,
    Json(payload): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let mut config = kinetic_core::config::KineticConfig::load();
    if let Some(mode) = payload.get("mode").and_then(|m| m.as_str()) {
        config.daemon.network_mode = mode.to_string();
    }
    let _ = config.save();
    Json(
        serde_json::json!({"status": "ok", "message": "Configuration saved. Restart daemon to apply."}),
    )
}
