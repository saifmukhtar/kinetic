//! API endpoints for consensus math, Name Difficulty Curve (NDC), and name validation.

use axum::{extract::{Path, Query, State}, Json};
use serde::{Deserialize, Serialize};
use kinetic_core::consensus_math::ConsensusParams;
use crate::api::ApiState;

/// Protocol-level consensus requirements for a name.
#[derive(Serialize)]
pub struct ProtocolRequirements {
    /// The base required iterations to register this name.
    pub iterations: u64,
    /// The mathematical tier classification (e.g., 5_chars).
    pub ndc_tier: String,
    /// The target network baseline time for this tier in minutes.
    pub network_reference_target_minutes: u64,
    /// True if the daemon is currently running in development mode.
    pub is_dev_mode: bool,
}

/// Host-specific time prediction based on startup micro-benchmarking.
#[derive(Serialize)]
pub struct LocalPrediction {
    /// True if the host IPS was successfully calibrated.
    pub calibrated: bool,
    /// Measured Iterations Per Second (derated for sustained thermal load).
    pub host_speed_ips: u64,
    /// The exact estimated wall-clock time in seconds.
    pub estimated_seconds: u64,
    /// A human-readable formatted time estimate.
    pub estimated_formatted: String,
    /// A subjective rating of the hardware speed.
    pub hardware_rating: String,
}

/// Response returned by the pre-flight difficulty calculator.
#[derive(Serialize)]
pub struct DifficultyResponse {
    /// The normalized name used for the calculation.
    pub name: String,
    /// The extracted apex label of the name.
    pub label: String,
    /// The character length of the label tier.
    pub label_length: usize,
    /// Protocol-level rules.
    pub protocol: ProtocolRequirements,
    /// Host-specific time prediction.
    pub local_prediction: LocalPrediction,
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

fn format_duration(secs: u64) -> String {
    if secs < 60 {
        format!("{} seconds", secs)
    } else {
        let mins = secs / 60;
        let rem = secs % 60;
        if rem == 0 {
            format!("{} minutes", mins)
        } else {
            format!("{} minutes {} seconds", mins, rem)
        }
    }
}

/// Retrieves the base difficulty (required VDF iterations) to register a specific name.
pub async fn handle_get_difficulty(
    State(state): State<ApiState>,
    Path(name): Path<String>,
) -> Json<DifficultyResponse> {
    let normalized = kinetic_core::types::names::normalize_name(&name);
    let params = ConsensusParams::default();
    let iterations = params.iterations(&normalized);
    let apex = kinetic_core::types::names::extract_apex_name(&normalized).to_string();
    let label = apex.strip_suffix(kinetic_core::constants::NSP_SUFFIX).unwrap_or(&apex).to_string();
    let label_length = label.len();
    
    let ndc_tier = format!("{}_chars", label_length);
    // Baseline network expectation (assume ~100k IPS baseline for rough target minutes)
    // 3 char: 300,000,000 / 100k = 3000s (50m)
    // 4 char: 75,000,000 / 100k = 750s (12.5m)
    let network_reference_target_minutes = (iterations / 100_000) / 60;
    
    let host_speed_ips = state.host_speed_ips;
    let estimated_seconds = iterations / std::cmp::max(host_speed_ips, 1);
    
    let rating = if host_speed_ips > 140_000 {
        "Fast"
    } else if host_speed_ips > 70_000 {
        "Average"
    } else {
        "Slow"
    };

    let rating_str = format!("{} (x{:.1} relative to network baseline)", rating, host_speed_ips as f64 / 100_000.0);

    Json(DifficultyResponse {
        name: normalized,
        label,
        label_length,
        protocol: ProtocolRequirements {
            iterations,
            ndc_tier,
            network_reference_target_minutes,
            is_dev_mode: kinetic_core::config::is_dev_mode(),
        },
        local_prediction: LocalPrediction {
            calibrated: true,
            host_speed_ips,
            estimated_seconds,
            estimated_formatted: format_duration(estimated_seconds),
            hardware_rating: rating_str,
        }
    })
}

/// Calculates the decayed steal difficulty for an idle name.
/// Requires the client to pass `?kyns_idle=X` in the query string.
pub async fn handle_steal_difficulty(
    State(_state): State<ApiState>,
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
            original: req.name.clone(),
            normalized,
            is_valid: true,
            is_reserved,
            error: None,
        }),
        Err(e) => Json(ValidateResponse {
            original: req.name.clone(),
            normalized,
            is_valid: false,
            is_reserved,
            error: Some(e.to_string()),
        })
    }
}
