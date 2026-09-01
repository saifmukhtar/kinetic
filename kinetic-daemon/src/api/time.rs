use crate::api::ApiState;
use axum::{Json, extract::State};
use kinetic_core::traits::KynProvider;
use kinetic_core::types::clock::KineticTime;

/// Returns the current verified Kinetic Time from the daemon's internal state.
pub async fn handle_get_time(
    State(state): State<ApiState>,
) -> Result<Json<KineticTime>, crate::api::error::AppError> {
    let kyn_provider =
        kinetic_network::client::drand::DrandProvider::new(Some(state.storage.clone()));

    // Always prefer the cache for instantaneous responses,
    // the Heartbeat loop ensures this cache is populated.
    // If the cache somehow fails, fallback to local clock estimation.
    match kyn_provider.load_cached_kyn() {
        Ok(drand_data) => {
            let time = KineticTime::from_kyn(
                kinetic_core::types::Kyn(drand_data.kyn),
                kinetic_core::types::Kyn(kinetic_core::constants::KINETIC_GENESIS_KYN),
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
