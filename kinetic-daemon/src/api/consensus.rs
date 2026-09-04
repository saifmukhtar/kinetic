//! API endpoints for consensus math, Name Difficulty Curve (NDC), and name validation.

use axum::{extract::{Path, Query}, Json};
use serde::{Deserialize, Serialize};
use kinetic_core::consensus_math::ConsensusParams;

/// Response returned by the pre-flight difficulty calculator.
#[derive(Serialize)]
pub struct DifficultyResponse {
    /// The normalized name used for the calculation.
    pub name: String,
    /// The base required iterations to register this name.
    pub iterations: u64,
    /// The character length of the label tier.
    pub label_length: usize,
    /// True if the daemon is currently running in development mode (lower difficulty).
    pub dev_mode: bool,
}

/// Query parameters for fetching idle steal difficulty.
#[derive(Deserialize)]
pub struct StealQuery {
    /// The number of Kyns the name has been idle (since the last heartbeat).
    pub kyns_idle: Option<u64>,
}

/// Response returned by the steal difficulty calculator.
#[derive(Serialize)]
pub struct StealDifficultyResponse {
    /// The normalized name used for the calculation.
    pub name: String,
    /// The base required iterations to register this name if it was perfectly new.
    pub base_iterations: u64,
    /// The number of Kyns the name has been idle.
    pub kyns_idle: u64,
    /// The current heavily decayed iterations required to take over the name.
    pub current_iterations: u64,
    /// The exact decay multiplier applied to the base iterations.
    pub decay_multiplier: f64,
}

/// Request to validate a potential name.
#[derive(Deserialize)]
pub struct ValidateRequest {
    /// The raw string name to validate.
    pub name: String,
}

/// Response returned after validating a name.
#[derive(Serialize)]
pub struct ValidateResponse {
    /// The original string provided.
    pub original: String,
    /// The fully canonical normalized string.
    pub normalized: String,
    /// True if the name passes all syntax, length, and LDH validation rules.
    pub is_valid: bool,
    /// True if the name is reserved and cannot be registered via normal PoW.
    pub is_reserved: bool,
    /// A human-readable error if validation failed.
    pub error: Option<String>,
}

/// Retrieves the base difficulty (required VDF iterations) to register a specific name.
pub async fn handle_get_difficulty(
    Path(name): Path<String>,
) -> Json<DifficultyResponse> {
    let normalized = kinetic_core::types::names::normalize_name(&name);
    let params = ConsensusParams::default();
    let iterations = params.iterations(&normalized);
    let apex = kinetic_core::types::names::extract_apex_name(&normalized);
    let label = apex.strip_suffix(kinetic_core::constants::NSP_SUFFIX).unwrap_or(&apex);
    
    Json(DifficultyResponse {
        name: normalized,
        iterations,
        label_length: label.len(),
        dev_mode: kinetic_core::config::is_dev_mode(),
    })
}

/// Calculates the decayed steal difficulty for an idle name.
/// Requires the client to pass `?kyns_idle=X` in the query string.
pub async fn handle_steal_difficulty(
    Path(name): Path<String>,
    Query(query): Query<StealQuery>,
) -> Result<Json<StealDifficultyResponse>, crate::api::error::AppError> {
    let normalized = kinetic_core::types::names::normalize_name(&name);
    let params = ConsensusParams::default();
    let base_iterations = params.iterations(&normalized);
    
    let kyns_idle = match query.kyns_idle {
        Some(idle) => idle,
        None => {
            return Err(crate::api::error::AppError::from(
                kinetic_core::error::RestApiError::BadRequest(
                    "Missing required query parameter: kyns_idle".to_string(),
                )
            ));
        }
    };

    let current_iterations = params.steal_diff(base_iterations, kyns_idle);
    let decay_multiplier = current_iterations as f64 / base_iterations as f64;

    Ok(Json(StealDifficultyResponse {
        name: normalized,
        base_iterations,
        kyns_idle,
        current_iterations,
        decay_multiplier,
    }))
}

/// Validates a potential name string according to Kinetic's core naming rules.
pub async fn handle_validate_name(
    Json(req): Json<ValidateRequest>,
) -> Json<ValidateResponse> {
    let normalized = kinetic_core::types::names::normalize_name(&req.name);
    let is_reserved = kinetic_core::types::names::is_reserved_name(&normalized);
    
    match kinetic_core::types::names::is_valid_apex_name(&normalized) {
        Ok(_) => Json(ValidateResponse {
            original: req.name,
            normalized,
            is_valid: true,
            is_reserved,
            error: None,
        }),
        Err(e) => Json(ValidateResponse {
            original: req.name,
            normalized,
            is_valid: false,
            is_reserved,
            error: Some(e.to_string()),
        })
    }
}
