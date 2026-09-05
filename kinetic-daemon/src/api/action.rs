//! HTTP REST API handlers for querying the Governance transparency layer.

use axum::Json;
use std::collections::HashMap;
use serde::Serialize;
use kinetic_local::governance::GLOBAL_GOVERNANCE_STATE;

/// A frontend-friendly representation of the Governance State.
#[derive(Serialize)]
pub struct GovernanceStatusResponse {
    /// Genesis Kyn when governance tracking started.
    pub genesis_kyn: u64,
    /// Active ML-DSA-65 root public key controlling the network (hex encoded).
    pub active_sovereign_key_hex: Option<String>,
    /// Master boolean flag if the network is currently paused.
    pub is_halted: bool,
    /// The exact Kyn when the network was halted (if currently halted).
    pub halt_start_kyn: Option<u64>,
    /// Total number of drand kyns the network has been paused for since genesis.
    pub total_paused_kyns: u64,
}

/// Handles requests to retrieve the human-readable active governance state.
pub async fn handle_get_action_status() -> Result<Json<GovernanceStatusResponse>, crate::api::error::AppError> {
    let gov = GLOBAL_GOVERNANCE_STATE.lock().unwrap();
    
    let active_key_hex = gov.active_sovereign_key.as_ref().map(hex::encode);

    Ok(Json(GovernanceStatusResponse {
        genesis_kyn: gov.genesis_kyn.0,
        active_sovereign_key_hex: active_key_hex,
        is_halted: gov.is_halted,
        halt_start_kyn: gov.halt_start_kyn.map(|k| k.0),
        total_paused_kyns: gov.total_paused_kyns,
    }))
}

/// Handles requests to retrieve the list of mapped prime names.
pub async fn handle_get_prime_names() -> Result<Json<HashMap<String, String>>, crate::api::error::AppError> {
    let gov = GLOBAL_GOVERNANCE_STATE.lock().unwrap();
    
    let mut primes_hex = HashMap::new();
    for (name, pubkey_bytes) in &gov.mapped_prime_names {
        primes_hex.insert(name.clone(), hex::encode(pubkey_bytes));
    }

    Ok(Json(primes_hex))
}

/// Handles requests to retrieve the list of mapped infrastructure names.
pub async fn handle_get_infra_names() -> Result<Json<HashMap<String, String>>, crate::api::error::AppError> {
    let gov = GLOBAL_GOVERNANCE_STATE.lock().unwrap();
    
    let mut infra_hex = HashMap::new();
    for (name, pubkey_bytes) in &gov.mapped_infra_names {
        infra_hex.insert(name.clone(), hex::encode(pubkey_bytes));
    }

    Ok(Json(infra_hex))
}
