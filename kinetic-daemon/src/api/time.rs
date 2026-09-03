//! HTTP REST API handler for retrieving verified Kinetic network time.

use crate::api::ApiState;
use axum::{Json, extract::State};
use kinetic_core::types::clock::KineticTime;

/// Returns the current verified Kinetic Time from the daemon's internal state.
pub async fn handle_get_time(
    State(state): State<ApiState>,
) -> Result<Json<KineticTime>, crate::api::error::AppError> {
    let drand_client = kinetic_core::drand::DrandClient::new(Some(state.storage.clone()));

    // Read the latest verified Drand kyn directly from the local database cache.
    // We do NOT call `fetch_latest()` here to prevent spamming the external Drand network
    // on every UI tick. The background gossip/heartbeat services keep this cache fresh.
    match drand_client.load_cached_kyn() {
        Ok(drand_data) => {
            let time = KineticTime::from_kyn(
                drand_data.kyn,
                kinetic_core::constants::KINETIC_GENESIS_KYN,
            );
            Ok(Json(time))
        }
        Err(e) => {
            tracing::error!(error_code = e.code(), "Failed to read cached Drand kyn for /api/time: {}", e);
            // If offline, we could fallback mathematically here as well,
            // but since it's the daemon, returning an error ensures consumers
            // know the node isn't synced. The CLI implements the offline fallback.
            Err(crate::api::error::AppError(e.into()))
        }
    }
}
