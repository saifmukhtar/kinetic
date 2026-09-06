//! HTTP REST API handlers for querying the Governance transparency layer.

use axum::Json;
use kinetic_core::types::KynNetworkExt;
use kinetic_local::governance::GLOBAL_GOVERNANCE_STATE;
use serde::Serialize;
use std::collections::HashMap;

/// A period of time when the network was halted.
#[derive(Serialize)]
pub struct PausePeriod {
    /// The exact Kyn when the network was halted.
    pub start_kyn: u64,
    /// The exact Kyn when the network was resumed.
    pub end_kyn: u64,
}

/// High-level metrics summarizing the action state.
#[derive(Serialize)]
pub struct ActionMetrics {
    /// Count of mapped prime names (e.g., .kin).
    pub total_prime_names: usize,
    /// Count of mapped infrastructure root names.
    pub total_infra_names: usize,
    /// Total number of governance/action commands executed since genesis.
    pub total_executed_actions: usize,
}

/// A frontend-friendly representation of the Action/Governance State.
#[derive(Serialize)]
pub struct ActionStatusResponse {
    /// Genesis Kyn when governance tracking started.
    pub genesis_kyn: u64,
    /// The current exact network Kyn.
    pub current_kyn: u64,
    /// The mathematically verified uptime age of the network in kyns.
    pub active_kyn_age: u64,
    /// Active ML-DSA-65 root public key controlling the network (hex encoded).
    pub active_sovereign_key_hex: Option<String>,
    /// Master boolean flag if the network is currently paused.
    pub is_halted: bool,
    /// The exact Kyn when the network was halted (if currently halted).
    pub halt_start_kyn: Option<u64>,
    /// Total number of drand kyns the network has been paused for since genesis.
    pub total_paused_kyns: u64,
    /// The last time the network was paused (if ever).
    pub last_pause: Option<PausePeriod>,
    /// Summary metrics for the dashboard.
    pub metrics: ActionMetrics,
}

/// Handles requests to retrieve the human-readable active action state.
pub async fn handle_get_action_status(
    axum::extract::State(state): axum::extract::State<crate::api::ApiState>,
) -> Result<Json<ActionStatusResponse>, crate::api::error::AppError> {
    let gov = GLOBAL_GOVERNANCE_STATE.lock().map_err(|e| {
        let sys_err = kinetic_core::error::SystemError::MutexPoisoned(e.to_string());
        crate::api::error::AppError(kinetic_rpc::ApiError {
            error_type: format!("{}/errors/{}", kinetic_core::constants::DOCS_URL, sys_err.code()),
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

    let active_key_hex = gov.active_sovereign_key.as_ref().map(hex::encode);

    // Fetch verified Kyn from the node's constantly updating local cache
    let current_kyn = {
        let kyn_provider =
            kinetic_network::client::drand::DrandProvider::new(Some(state.storage.clone()));
        use kinetic_core::traits::KynProvider;
        match kyn_provider.load_cached_kyn() {
            Ok(kyn) => kyn.kyn,
            Err(_) => kinetic_core::types::Kyn::now_local().0, // Fallback to OS clock if DB is completely empty (genesis)
        }
    };

    let active_kyn_age = current_kyn
        .saturating_sub(gov.genesis_kyn.0)
        .saturating_sub(gov.total_paused_kyns);

    let last_pause = gov.pause_history.last().map(|(start, end)| PausePeriod {
        start_kyn: start.0,
        end_kyn: end.0,
    });

    let metrics = ActionMetrics {
        total_prime_names: gov.mapped_prime_names.len(),
        total_infra_names: gov.mapped_infra_names.len(),
        total_executed_actions: gov.executed_hashes.len(),
    };

    Ok(Json(ActionStatusResponse {
        genesis_kyn: gov.genesis_kyn.0,
        current_kyn,
        active_kyn_age,
        active_sovereign_key_hex: active_key_hex,
        is_halted: gov.is_halted,
        halt_start_kyn: gov.halt_start_kyn.map(|k| k.0),
        total_paused_kyns: gov.total_paused_kyns,
        last_pause,
        metrics,
    }))
}

/// Aggregated response containing both prime and infrastructure name mappings.
#[derive(Serialize)]
pub struct ActionNamesResponse {
    /// Mapped 1-character prime names (e.g., 'a', '7').
    pub primes: HashMap<String, String>,
    /// Mapped protocol infrastructure names (e.g., 'seed', 'node', 'api').
    pub infras: HashMap<String, String>,
}

/// Handles requests to retrieve all mapped Action names (primes and infras) in a single call.
pub async fn handle_get_action_names() -> Result<Json<ActionNamesResponse>, crate::api::error::AppError> {
    let gov = GLOBAL_GOVERNANCE_STATE.lock().map_err(|e| {
        let sys_err = kinetic_core::error::SystemError::MutexPoisoned(e.to_string());
        crate::api::error::AppError(kinetic_rpc::ApiError {
            error_type: format!("{}/errors/{}", kinetic_core::constants::DOCS_URL, sys_err.code()),
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

    let primes = gov
        .mapped_prime_names
        .iter()
        .map(|(name, pubkey_bytes)| (name.clone(), hex::encode(pubkey_bytes)))
        .collect::<HashMap<String, String>>();

    let infras = gov
        .mapped_infra_names
        .iter()
        .map(|(name, pubkey_bytes)| (name.clone(), hex::encode(pubkey_bytes)))
        .collect::<HashMap<String, String>>();

    Ok(Json(ActionNamesResponse { primes, infras }))
}

use crate::api::ApiState;
use crate::api::PublishResponse;
use axum::{extract::State, http::StatusCode};
use kinetic_core::traits::KynProvider;

/// Handles API requests to publish a `SignedGovernanceMessage` to the DHT/Gossip network.
///
/// # Errors
///
/// Returns an error if the governance message is invalid, quorum checks fail prematurely,
/// or publishing to the Gossipsub network fails.
pub async fn handle_publish_action(
    axum::extract::Extension(role): axum::extract::Extension<crate::api::Role>,
    State(state): State<ApiState>,
    Json(msg): Json<kinetic_core::governance::SignedGovernanceMessage>,
) -> Result<Json<PublishResponse>, (StatusCode, String)> {
    if !role.can_action() {
        return Err((
            StatusCode::FORBIDDEN,
            "Insufficient privileges: Requires Action or Admin role".to_string(),
        ));
    }
    tracing::info!("Received API publish request for Governance action");

    let current_kyn = {
        let kyn_provider =
            kinetic_network::client::drand::DrandProvider::new(Some(state.storage.clone()));
        use kinetic_core::types::clock::KynNetworkExt;
        match kyn_provider.load_cached_kyn() {
            Ok(kyn) => kyn.kyn,
            Err(_) => match kyn_provider.fetch_latest().await {
                Ok(kyn) => kyn.kyn,
                Err(_) => kinetic_core::types::Kyn::now_local().0,
            },
        }
    };

    let is_valid = {
        let mut gov = kinetic_local::governance::GLOBAL_GOVERNANCE_STATE
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        match kinetic_core::governance::process_governance_message(
            &mut gov,
            &msg,
            kinetic_types::clock::Kyn(current_kyn),
        ) {
            Ok(_) => {
                let path = kinetic_local::config::get_base_dir().join("action.db");
                if let Err(e) = kinetic_local::governance::save_governance_to_disk(&gov, &path) {
                    let err = kinetic_core::error::GovernanceError::StateSaveFailed;
                    tracing::error!(
                        error_code = err.code(),
                        "Failed to save modified governance state to disk: {}",
                        e
                    );
                }

                true
            }
            Err(e) => {
                tracing::warn!(
                    error_code = e.code(),
                    "Rejecting governance message via API: {}",
                    e
                );
                return Err((
                    StatusCode::BAD_REQUEST,
                    format!("Invalid governance message: {}", e),
                ));
            }
        }
    };

    if !is_valid {
        return Err((
            StatusCode::BAD_REQUEST,
            "Governance message validation failed".to_string(),
        ));
    }

    // Serialize and gossip
    let payload_bytes = match serde_json::to_vec(&msg) {
        Ok(b) => b,
        Err(e) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Serialization failed: {}", e),
            ));
        }
    };

    let mut envelope = vec![kinetic_types::network::NetworkOpcode::Governance as u8];
    envelope.extend(payload_bytes);

    match state
        .network
        .broadcast_gossip(kinetic_core::constants::GOSSIP_TOPIC_GLOBAL, envelope)
        .await
    {
        Ok(_) => {
            tracing::info!("Successfully published Governance Message to the Gossip network");
            Ok(Json(PublishResponse {
                status: "success".to_string(),
                message: "Governance action accepted and routed to P2P network".to_string(),
            }))
        }
        Err(e) => {
            let err = kinetic_core::error::GovernanceError::P2pPublishFailed;
            tracing::error!(
                error_code = err.code(),
                "Failed to publish Governance Message to P2P network: {}",
                e
            );
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to broadcast: {}", e),
            ))
        }
    }
}
