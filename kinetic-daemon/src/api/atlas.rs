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
) -> axum::response::Response {
    if role != crate::api::Role::Atlas && !role.is_admin() {
        return axum::response::Response::builder()
            .status(axum::http::StatusCode::FORBIDDEN)
            .body(axum::body::Body::from(
                "Forbidden: Requires Atlas or Admin role",
            ))
            .unwrap();
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
            axum::response::Response::builder()
                .status(axum::http::StatusCode::OK)
                .body(axum::body::Body::from("Atlas NSPs synced successfully"))
                .unwrap()
        }
        Err(_) => {
            tracing::error!("KIN-DMN-006: Failed to acquire write lock on atlas_nsps");
            axum::response::Response::builder()
                .status(axum::http::StatusCode::INTERNAL_SERVER_ERROR)
                .body(axum::body::Body::from("Internal Server Error"))
                .unwrap()
        }
    }
}
