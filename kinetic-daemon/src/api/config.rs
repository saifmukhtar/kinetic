//! HTTP REST API endpoints for daemon configuration, node status, owned names, and governance state.

use super::*;
use axum::{
    Json,
    extract::{Extension, State},
};

/// Handles requests to retrieve the current daemon configuration.
pub async fn handle_get_config(
    Extension(role): Extension<Role>,
    State(_state): State<ApiState>,
) -> Result<Json<serde_json::Value>, crate::api::error::AppError> {
    if !role.can_system() {
        return Err(crate::api::error::AppError::from(
            kinetic_core::error::RestApiError::InsufficientPrivileges,
        ));
    }
    let config = kinetic_local::config::load_config();
    Ok(Json(serde_json::json!({
        "status": "ok",
        "config": config
    })))
}

/// Handles requests to retrieve a list of names owned by this node.
pub async fn handle_owned_names(
    Extension(role): Extension<Role>,
    State(state): State<ApiState>,
) -> Result<Json<Vec<String>>, crate::api::error::AppError> {
    if !role.can_nrs() {
        return Err(crate::api::error::AppError::from(
            kinetic_core::error::RestApiError::InsufficientPrivileges,
        ));
    }
    let owned_key = kinetic_core::constants::DB_PREFIX_OWNED_NAMES;
    let owned_names: Vec<String> = match state.storage.get(owned_key) {
        Ok(Some(bytes)) => match serde_json::from_slice(&bytes) {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(
                    error = ?kinetic_core::error::StorageError::DeserializationFailed(e.to_string()),
                    "{}",
                    kinetic_core::error::StorageError::DeserializationFailed(e.to_string()).user_message()
                );
                Vec::new()
            }
        },
        _ => Vec::new(),
    };
    Ok(Json(owned_names))
}

/// Handles requests to retrieve the current network status (peer count, DHT size, uptime).
pub async fn handle_network_status(State(state): State<ApiState>) -> Result<Json<serde_json::Value>, crate::api::error::AppError> {
    match state.network.get_network_status().await {
        Ok(status) => Ok(Json(status)),
        Err(e) => Err(crate::api::error::AppError::from(e)),
    }
}

/// Handles requests to manually trigger a Kademlia network bootstrap.
pub async fn handle_network_bootstrap(
    axum::extract::Extension(role): axum::extract::Extension<crate::api::Role>,
    State(state): State<ApiState>,
) -> Result<Json<serde_json::Value>, crate::api::error::AppError> {
    if !role.can_system() {
        return Err(crate::api::error::AppError::from(
            kinetic_core::error::RestApiError::InsufficientPrivileges,
        ));
    }

    match state.network.rebootstrap_network().await {
        Ok(_) => Ok(Json(serde_json::json!({
            "status": "success",
            "message": "Network bootstrap initiated."
        }))),
        Err(e) => Err(crate::api::error::AppError::from(e)),
    }
}

/// Handles requests to retrieve the current Libp2p AutoNAT status (e.g. Public, Private, Unknown).
pub async fn handle_network_nat(State(state): State<ApiState>) -> Result<Json<serde_json::Value>, crate::api::error::AppError> {
    match state.network.get_network_status().await {
        Ok(status) => Ok(Json(serde_json::json!({ "nat_status": status.get("nat_status").unwrap_or(&serde_json::json!("Unknown")) }))),
        Err(e) => Err(crate::api::error::AppError::from(e)),
    }
}

/// Handles requests to retrieve the list of currently banned spam peers and their expiration kyn.
pub async fn handle_network_banned(State(state): State<ApiState>) -> Result<Json<serde_json::Value>, crate::api::error::AppError> {
    match state.network.get_banned_peers().await {
        Ok(peers) => {
            let json_peers: Vec<serde_json::Value> = peers.into_iter().map(|(id, exp)| {
                serde_json::json!({ "peer_id": id, "expires_at_kyn": exp })
            }).collect();
            Ok(Json(serde_json::json!({ "banned_peers": json_peers })))
        },
        Err(e) => Err(crate::api::error::AppError::from(e)),
    }
}

/// Handles requests to retrieve the list of connected Peer IDs.
pub async fn handle_network_peers(State(state): State<ApiState>) -> Result<Json<Vec<String>>, crate::api::error::AppError> {
    match state.network.get_connected_peers().await {
        Ok(peers) => Ok(Json(peers)),
        Err(e) => Err(crate::api::error::AppError::from(e)),
    }
}

/// Handles requests to update the daemon configuration.
pub async fn handle_set_config(
    Extension(role): Extension<Role>,
    State(_state): State<ApiState>,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, crate::api::error::AppError> {
    if !role.can_system() {
        return Err(crate::api::error::AppError::from(
            kinetic_core::error::RestApiError::InsufficientPrivileges,
        ));
    }

    if let Some(config_payload) = payload.get("config") {
        match serde_json::from_value::<kinetic_core::config::KineticConfig>(config_payload.clone())
        {
            Ok(new_config) => {
                if let Err(e) = new_config.validate() {
                    return Err(crate::api::error::AppError(e.into()));
                }
                
                let _ = kinetic_local::config::save_config(&new_config);
                Ok(Json(serde_json::json!({
                    "status": "ok",
                    "message": "Configuration saved. Restart daemon to apply."
                })))
            }
            Err(e) => {
                let err = kinetic_core::error::ConfigError::InvalidApiUpdate(format!(
                    "Invalid config payload format: {}",
                    e
                ));
                Err(crate::api::error::AppError(kinetic_rpc::ApiError::from(
                    err,
                )))
            }
        }
    } else {
        let err = kinetic_core::error::ConfigError::InvalidApiUpdate(
            "Missing 'config' object in payload.".to_string(),
        );
        Err(crate::api::error::AppError(kinetic_rpc::ApiError::from(
            err,
        )))
    }
}

/// Handles requests to check the daemon health.
pub async fn handle_get_health(State(state): State<ApiState>) -> Json<serde_json::Value> {
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
pub async fn handle_get_peer_id(
    State(state): State<ApiState>,
) -> Result<String, crate::api::error::AppError> {
    match state.network.get_network_status().await {
        Ok(status) => {
            if let Some(peer_id) = status.get("peer_id").and_then(|p| p.as_str()) {
                Ok(peer_id.to_string())
            } else {
                Err(crate::api::error::AppError(kinetic_rpc::ApiError::from(
                    kinetic_core::error::ResolutionError::Offline,
                )))
            }
        }
        Err(_) => Err(crate::api::error::AppError(kinetic_rpc::ApiError::from(
            kinetic_core::error::ResolutionError::Internal {
                message: "Network channel closed".to_string(),
                source: None,
            },
        ))),
    }
}

use axum::response::IntoResponse;
use axum::http::header;

/// Exports the local Proxy Root CA certificate for browser installation.
pub async fn handle_get_ca_cert(
) -> Result<impl IntoResponse, crate::api::error::AppError> {
    let base_config_dir = kinetic_local::config::get_base_dir();
    let ca_path = base_config_dir.join("root_ca.crt");
    
    match tokio::fs::read_to_string(&ca_path).await {
        Ok(cert) => {
            let headers = [
                (header::CONTENT_TYPE, "application/x-x509-ca-cert"),
                (header::CONTENT_DISPOSITION, "attachment; filename=\"kinetic_root_ca.crt\""),
            ];
            Ok((headers, cert))
        }
        Err(e) => {
            tracing::error!("Failed to read CA cert from {:?}: {}", ca_path, e);
            Err(crate::api::error::AppError::from(
                kinetic_core::error::RestApiError::NotFound,
            ))
        }
    }
}

/// Flushes the local DNS resolution memory cache.
pub async fn handle_dns_flush(
    Extension(role): Extension<Role>,
    State(state): State<ApiState>,
) -> Result<Json<serde_json::Value>, crate::api::error::AppError> {
    if !role.can_system() {
        return Err(crate::api::error::AppError::from(
            kinetic_core::error::RestApiError::InsufficientPrivileges,
        ));
    }
    
    {
        let mut cache = state.dns_cache.lock().await;
        cache.flush();
    }
    
    Ok(Json(serde_json::json!({
        "status": "success",
        "message": "Local DNS resolution cache flushed"
    })))
}
