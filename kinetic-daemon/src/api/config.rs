use super::*;
use axum::{extract::{Path, State}, Json, http::StatusCode};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tracing::{error, info, warn};
use kinetic_core::types::{Reveal, Commitment, CommitRequest};
use kinetic_core::traits::StorageEngine;


pub async fn handle_config(State(state): State<ApiState>) -> Json<serde_json::Value> {
    let config = kinetic_core::config::KineticConfig::load();
    Json(serde_json::json!({
        "token": state.auth_token,
        "mode": config.daemon.network_mode
    }))
}

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

