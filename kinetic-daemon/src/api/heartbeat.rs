//! API endpoints for manually broadcasting heartbeats and checking real-time DHT heartbeat status.

use crate::api::ApiState;
use axum::{
    Json,
    extract::{Path, State},
};
use kinetic_core::constants;
use kinetic_core::types::Heartbeat;
use serde::Serialize;

/// Represents the DHT heartbeat status of a locally owned name.
#[derive(Serialize)]
pub struct HeartbeatStatusResponse {
    /// The apex name.
    pub name: String,
    /// The calculated status (Active, Stale, Idle).
    pub status: String,
    /// The Kyn number of the last accepted heartbeat on the DHT.
    pub latest_kyn: u64,
    /// The number of Kyns this name has been idle.
    pub kyns_idle: u64,
}

/// Response returned when querying the status of all locally owned names.
#[derive(Serialize)]
pub struct HeartbeatsResponse {
    /// The current network Kyn.
    pub current_kyn: u64,
    /// Status of each locally owned name.
    pub names: Vec<HeartbeatStatusResponse>,
}

/// Fetches the real-time DHT heartbeat status of all locally owned names.
pub async fn handle_get_heartbeats(
    State(state): State<ApiState>,
) -> Result<Json<HeartbeatsResponse>, crate::api::error::AppError> {
    let owned_key = constants::DB_PREFIX_OWNED_NAMES;
    let owned_names: Vec<String> = match state.storage.get(owned_key) {
        Ok(Some(bytes)) => serde_json::from_slice(&bytes).unwrap_or_default(),
        _ => Vec::new(),
    };

    let current_kyn = state.network.get_current_kyn().await.unwrap_or(0);

    let mut handles = Vec::new();
    for name in owned_names {
        let state = state.clone();
        let name_clone = name.clone();
        handles.push(tokio::spawn(async move {
            let res = state.network.resolve_heartbeat(&name_clone).await;
            (name_clone, res)
        }));
    }

    let mut statuses = Vec::new();
    for handle in handles {
        if let Ok((name, network_res)) = handle.await {
            match network_res {
                Ok(bytes) => {
                    if let Ok(hb) = serde_json::from_slice::<Heartbeat>(&bytes) {
                        let age = current_kyn.saturating_sub(hb.latest_kyn);
                        let status = if age <= 200 {
                            "Active"
                        } else if age <= 28800 {
                            "Stale"
                        } else {
                            "Idle"
                        };
                        statuses.push(HeartbeatStatusResponse {
                            name,
                            status: status.to_string(),
                            latest_kyn: hb.latest_kyn,
                            kyns_idle: age,
                        });
                    } else {
                        statuses.push(HeartbeatStatusResponse {
                            name,
                            status: "Unknown (Parse Error)".to_string(),
                            latest_kyn: 0,
                            kyns_idle: 0,
                        });
                    }
                }
                Err(_) => {
                    statuses.push(HeartbeatStatusResponse {
                        name,
                        status: "Idle (Not Found on DHT)".to_string(),
                        latest_kyn: 0,
                        kyns_idle: 0,
                    });
                }
            }
        }
    }

    Ok(Json(HeartbeatsResponse {
        current_kyn,
        names: statuses,
    }))
}

/// Manually constructs and broadcasts a heartbeat for a specific name to the DHT.
pub async fn handle_post_heartbeat(
    axum::extract::Extension(role): axum::extract::Extension<crate::api::Role>,
    State(state): State<ApiState>,
    Path(name): Path<String>,
) -> Result<Json<serde_json::Value>, crate::api::error::AppError> {
    if !role.can_nrs() {
        return Err(crate::api::error::AppError::from(
            kinetic_core::error::RestApiError::InsufficientPrivileges,
        ));
    }
    let current_kyn = state.network.get_current_kyn().await.unwrap_or(0);

    let mut heartbeat = Heartbeat {
        name: name.clone(),
        latest_kyn: current_kyn,
        signature: vec![],
        authorization: None,
    };

    let signable_bytes = heartbeat.signable_bytes(constants::NETWORK_SALT);
    let keypair = state.daemon_keypair.clone();

    let sig_bytes = tokio::task::spawn_blocking(move || keypair.sign(&signable_bytes))
        .await
        .unwrap();
    heartbeat.signature = sig_bytes;

    let payload = serde_json::to_vec(&heartbeat).unwrap();

    match state.network.publish_heartbeat(&name, payload).await {
        Ok(_) => Ok(Json(serde_json::json!({
            "status": "success",
            "message": format!("Manually broadcasted heartbeat for {}", name),
            "kyn": current_kyn
        }))),
        Err(e) => Err(crate::api::error::AppError::from(e)),
    }
}
