//! HTTP REST API handler for retrieving verified Kinetic network time.

use crate::api::ApiState;
use axum::{extract::State, http::StatusCode, Json};
use kinetic_core::types::clock::KineticTime;

/// Returns the current verified Kinetic Time from the daemon's internal state.
pub async fn handle_get_time(
    State(state): State<ApiState>,
) -> Result<Json<KineticTime>, (StatusCode, String)> {
    let drand_client = kinetic_core::drand::DrandClient::new(Some(state.storage.clone()));
    
    // Fetch the latest verified Drand pulse
    match drand_client.fetch_latest().await {
        Ok(drand_data) => {
            let time = KineticTime::from_drand_round(drand_data.round);
            Ok(Json(time))
        }
        Err(e) => {
            tracing::error!("Failed to fetch Drand round for /api/time: {}", e);
            // If offline, we could fallback mathematically here as well, 
            // but since it's the daemon, returning an error ensures consumers 
            // know the node isn't synced. The CLI implements the offline fallback.
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to fetch synchronized network time".to_string(),
            ))
        }
    }
}
