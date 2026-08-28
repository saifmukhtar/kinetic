use crate::api::ApiState;
use axum::{Json, extract::State};
use serde::{Deserialize, Serialize};

/// Payload sent by the kinetic-atlas bridge containing the list of registered foreign NSPs.
#[derive(Deserialize, Serialize, Debug)]
pub struct AtlasSyncPayload {
    /// List of NSPs supported by the atlas bridge.
    pub nsps: Vec<String>,
}

/// Webhook endpoint for the kinetic-atlas bridge to push updated NSP routing tables.
/// This updates the in-memory HashSet used by the DNS resolver.
pub async fn handle_atlas_sync(
    axum::extract::Extension(role): axum::extract::Extension<crate::api::Role>,
    State(state): State<ApiState>,
    Json(payload): Json<AtlasSyncPayload>,
) -> Result<String, crate::api::error::AppError> {
    if role != crate::api::Role::Atlas && !role.is_admin() {
        return Err(crate::api::error::AppError(kinetic_core::ApiError {
            error_type: format!("{}/errors/KIN-API-001", kinetic_core::constants::DOCS_URL),
            title: "Unauthorized".to_string(),
            status: 403,
            detail: "Forbidden: Requires Atlas or Admin role".to_string(),
            instance: None,
            code: "KIN-API-001".to_string(),
            retryable: false,
            details: serde_json::Value::Null,
            request_id: "".to_string(),
        }));
    }

    let mut clean_nsps = std::collections::HashSet::new();

    // Normalize and add each NSP
    for nsp in payload.nsps {
        let mut t = nsp.trim().to_lowercase();
        // Remove leading dot if present
        if t.starts_with('.') {
            t.remove(0);
        }
        if !t.is_empty() {
            clean_nsps.insert(format!(".{}", t));
        }
    }

    match state.atlas_nsps.write() {
        Ok(mut lock) => {
            *lock = clean_nsps.clone();
            tracing::info!(
                "Atlas Bridge synced {} NSPs successfully: {:?}",
                clean_nsps.len(),
                clean_nsps
            );

            // Return 200 OK
            Ok("Atlas NSPs synced successfully".to_string())
        }
        Err(_) => {
            tracing::error!("KIN-DBE-004: Failed to acquire write lock on atlas_nsps");
            Err(crate::api::error::AppError(kinetic_core::ApiError {
                error_type: format!("{}/errors/KIN-DBE-004", kinetic_core::constants::DOCS_URL),
                title: "Internal Server Error".to_string(),
                status: 500,
                detail: "Failed to acquire write lock on atlas_nsps".to_string(),
                instance: None,
                code: "KIN-DBE-004".to_string(),
                retryable: true,
                details: serde_json::Value::Null,
                request_id: "".to_string(),
            }))
        }
    }
}
