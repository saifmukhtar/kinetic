//! API endpoints for manually broadcasting heartbeats and checking real-time DHT heartbeat status.

use crate::api::ApiState;
use axum::{
    Json,
    extract::{Path, State},
};
use kinetic_core::constants;
use kinetic_core::types::{Heartbeat, KynNetworkExt};
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

/// Active heartbeat freshness window (200 Kyns ~ 10 minutes at 3s/kyn).
const ACTIVE_HEARTBEAT_MAX_KYNS: u64 = 200;
/// Expiration window (28,800 Kyns = 1 Prism / 24 hours at 3s/kyn).
const STALE_HEARTBEAT_MAX_KYNS: u64 = 28_800;

/// Safely fetches the current Kyn using the network client, with verified local database cache fallback.
async fn get_safe_current_kyn(state: &ApiState) -> u64 {
    if let Ok(kyn) = state.network.get_current_kyn().await
        && kyn > 0 {
            return kyn;
        }

    let kyn_provider =
        kinetic_network::client::drand::DrandProvider::new(Some(state.storage.clone()));
    use kinetic_core::traits::KynProvider;
    match kyn_provider.load_cached() {
        Ok(kyn) if kyn.kyn > 0 => kyn.kyn,
        _ => kinetic_core::types::Kyn::now_local().0,
    }
}

/// Fetches the real-time DHT heartbeat status of all locally owned names.
pub async fn handle_get_heartbeats(
    State(state): State<ApiState>,
) -> Result<Json<HeartbeatsResponse>, crate::api::error::AppError> {
    let owned_key = constants::DB_PREFIX_OWNED_NAMES;
    let owned_names: Vec<String> = match state.storage.get(owned_key) {
        Ok(Some(bytes)) => match serde_json::from_slice(&bytes) {
            Ok(v) => v,
            Err(e) => {
                let err = kinetic_core::error::StorageError::DeserializationFailed(e.to_string());
                tracing::error!(error = ?err, "{}", err.user_message());
                return Err(crate::api::error::AppError::from(err));
            }
        },
        Ok(None) => Vec::new(),
        Err(e) => return Err(crate::api::error::AppError::from(e)),
    };

    let current_kyn = get_safe_current_kyn(&state).await;

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
                        let status = if age <= ACTIVE_HEARTBEAT_MAX_KYNS {
                            "Active"
                        } else if age <= STALE_HEARTBEAT_MAX_KYNS {
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
    if !role.can_heartbeat() {
        return Err(crate::api::error::AppError::from(
            kinetic_core::error::RestApiError::InsufficientPrivileges,
        ));
    }

    let normalized = kinetic_core::types::names::normalize_name(&name);
    if let Err(e) = kinetic_core::types::names::is_valid_apex_name(&normalized) {
        return Err(crate::api::error::AppError(kinetic_rpc::ApiError::from(e)));
    }

    let current_kyn = get_safe_current_kyn(&state).await;

    let mut heartbeat = Heartbeat {
        name: normalized.clone(),
        latest_kyn: current_kyn,
        signature: vec![],
        authorization: None,
    };

    let signable_bytes = heartbeat.signable_bytes(constants::NETWORK_SALT);
    let keypair = state.daemon_keypair.clone();

    let sig_bytes = tokio::task::spawn_blocking(move || keypair.sign(&signable_bytes))
        .await
        .map_err(|e| {
            let sys_err = kinetic_core::error::SystemError::ServerCrashed(e.to_string());
            crate::api::error::AppError(kinetic_rpc::ApiError {
                error_type: sys_err.error_type_uri(),
                title: "Internal Server Error".to_string(),
                status: 500,
                detail: sys_err.user_message(),
                instance: None,
                code: sys_err.code().to_string(),
                retryable: sys_err.is_retryable(),
                details: serde_json::Value::Null,
                request_id: "".to_string(),
            })
        })?;
    heartbeat.signature = sig_bytes;

    let payload = serde_json::to_vec(&heartbeat).map_err(|e| {
        crate::api::error::AppError::from(
            kinetic_core::error::RestApiError::BadRequest(format!(
                "Failed to serialize heartbeat: {}",
                e
            )),
        )
    })?;

    match state.network.publish_heartbeat(&normalized, payload).await {
        Ok(_) => Ok(Json(serde_json::json!({
            "status": "success",
            "message": format!("Manually broadcasted heartbeat for {}", normalized),
            "kyn": current_kyn
        }))),
        Err(e) => Err(crate::api::error::AppError::from(e)),
    }
}

use serde::Deserialize;

/// Request payload for manually broadcasting a Fat Heartbeat.
#[derive(Deserialize)]
pub struct FatHeartbeatRequest {
    /// The private key of the hot key, hex encoded, to sign the heartbeat.
    pub hot_key_hex: String,
    /// The master-key authorized delegation proof.
    pub authorized_manifest: kinetic_core::types::identity::AuthorizedManifest,
}

/// Manually constructs and broadcasts a Fat Heartbeat for a specific name to the DHT,
/// using a delegated hot key and an authorized manifest instead of the daemon master key.
pub async fn handle_post_fat_heartbeat(
    axum::extract::Extension(role): axum::extract::Extension<crate::api::Role>,
    State(state): State<ApiState>,
    Path(name): Path<String>,
    Json(req): Json<FatHeartbeatRequest>,
) -> Result<Json<serde_json::Value>, crate::api::error::AppError> {
    if !role.can_heartbeat() {
        return Err(crate::api::error::AppError::from(
            kinetic_core::error::RestApiError::InsufficientPrivileges,
        ));
    }

    let normalized = kinetic_core::types::names::normalize_name(&name);
    if let Err(e) = kinetic_core::types::names::is_valid_apex_name(&normalized) {
        return Err(crate::api::error::AppError(kinetic_rpc::ApiError::from(e)));
    }

    // Verify the capability is present in the manifest
    let has_cap = req.authorized_manifest.manifest.services.iter()
        .any(|s| s.service_type == "kinetic.capability.heartbeat");
    if !has_cap {
        return Err(crate::api::error::AppError::from(
            kinetic_core::error::RestApiError::BadRequest("Provided AuthorizedManifest does not contain kinetic.capability.heartbeat capability.".to_string()),
        ));
    }

    // Load the hot key
    let hot_key_bytes = hex::decode(&req.hot_key_hex).map_err(|e| {
        crate::api::error::AppError::from(kinetic_core::error::RestApiError::BadRequest(format!("Invalid hot_key_hex: {}", e)))
    })?;
    let keypair = kinetic_primitives::keys::KineticKeypair::from_slice(&hot_key_bytes).map_err(|e| {
         crate::api::error::AppError::from(kinetic_core::error::RestApiError::BadRequest(format!("Invalid ML-DSA keypair: {}", e)))
    })?;

    let current_kyn = get_safe_current_kyn(&state).await;

    let mut heartbeat = Heartbeat {
        name: normalized.clone(),
        latest_kyn: current_kyn,
        signature: vec![],
        authorization: Some(Box::new(req.authorized_manifest)),
    };

    let signable_bytes = heartbeat.signable_bytes(constants::NETWORK_SALT);
    
    let sig_bytes = tokio::task::spawn_blocking(move || keypair.sign(&signable_bytes))
        .await
        .map_err(|e| {
            let sys_err = kinetic_core::error::SystemError::ServerCrashed(e.to_string());
            crate::api::error::AppError(kinetic_rpc::ApiError {
                error_type: sys_err.error_type_uri(),
                title: "Internal Server Error".to_string(),
                status: 500,
                detail: sys_err.user_message(),
                instance: None,
                code: sys_err.code().to_string(),
                retryable: sys_err.is_retryable(),
                details: serde_json::Value::Null,
                request_id: "".to_string(),
            })
        })?;
    heartbeat.signature = sig_bytes;

    let payload = serde_json::to_vec(&heartbeat).map_err(|e| {
        crate::api::error::AppError::from(
            kinetic_core::error::RestApiError::BadRequest(format!(
                "Failed to serialize fat heartbeat: {}",
                e
            )),
        )
    })?;

    match state.network.publish_heartbeat(&normalized, payload).await {
        Ok(_) => Ok(Json(serde_json::json!({
            "status": "success",
            "message": format!("Manually broadcasted Fat Heartbeat for {}", normalized),
            "kyn": current_kyn
        }))),
        Err(e) => Err(crate::api::error::AppError::from(e)),
    }
}
