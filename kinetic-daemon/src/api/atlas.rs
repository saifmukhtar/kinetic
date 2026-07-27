use crate::api::ApiState;
use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};

/// Payload sent by the kinetic-atlas bridge containing the list of registered foreign TLDs.
#[derive(Deserialize, Serialize, Debug)]
pub struct AtlasSyncPayload {
    /// List of TLDs supported by the atlas bridge.
    pub tlds: Vec<String>,
}

/// Webhook endpoint for the kinetic-atlas bridge to push updated TLD routing tables.
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

    let mut clean_tlds = std::collections::HashSet::new();

    // Normalize and add each TLD
    for tld in payload.tlds {
        let mut t = tld.trim().to_lowercase();
        // Remove leading dot if present
        if t.starts_with('.') {
            t.remove(0);
        }
        if !t.is_empty() {
            clean_tlds.insert(format!(".{}", t));
        }
    }

    match state.atlas_tlds.write() {
        Ok(mut lock) => {
            *lock = clean_tlds.clone();
            tracing::info!(
                "Atlas Bridge synced {} TLDs successfully: {:?}",
                clean_tlds.len(),
                clean_tlds
            );

            // Return 200 OK
            axum::response::Response::builder()
                .status(axum::http::StatusCode::OK)
                .body(axum::body::Body::from("Atlas TLDs synced successfully"))
                .unwrap()
        }
        Err(_) => {
            tracing::error!("Failed to acquire write lock on atlas_tlds");
            axum::response::Response::builder()
                .status(axum::http::StatusCode::INTERNAL_SERVER_ERROR)
                .body(axum::body::Body::from("Internal Server Error"))
                .unwrap()
        }
    }
}
