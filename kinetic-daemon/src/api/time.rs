//! HTTP REST API endpoints for resolving canonical network time.
//!
//! ## Layer 8 Architecture: Time Oracle Interface
//! This module exposes a fast, synchronous endpoint for the Desktop UI to fetch 
//! the current Time Oracle epoch (KYN). Because fetching directly from the network 
//! requires an asynchronous mesh query, this endpoint strictly returns the 
//! `kinetic-storage` cached value, which is continuously kept fresh by the 
//! daemon's background Heartbeat worker.

use crate::api::ApiState;
use axum::{Json, extract::State};
use kinetic_core::traits::KynProvider;
use kinetic_kyn::types::CrystallizedKyn;

/// Returns the current verified Kinetic Time from the daemon's internal state.
pub async fn handle_get_time(
    State(state): State<ApiState>,
) -> Result<Json<CrystallizedKyn>, crate::api::error::AppError> {
    let kyn_provider =
        kinetic_network::client::time_oracle::TimeOracleProvider::new(Some(state.storage.clone()));

    // Always prefer the cache for instantaneous responses,
    // the Heartbeat loop ensures this cache is populated.
    // If the cache somehow fails, fallback to local clock estimation.
    match kyn_provider.load_cached() {
        Ok(drand_data) => {
            let time = CrystallizedKyn::from_kyn(
                kinetic_kyn::types::Kyn(drand_data.kyn),
                kinetic_kyn::types::Kyn(kinetic_core::constants::KINETIC_GENESIS_KYN),
            );
            Ok(Json(time))
        }
        Err(e) => {
            tracing::error!(
                error_code = e.code(),
                "Failed to read cached Time Oracle kyn for /api/v1/micro/time/current: {}",
                e
            );
            // If offline, we could fallback mathematically here as well,
            // but since it's the daemon, returning an error ensures consumers
            // know the node isn't synced. The CLI implements the offline fallback.
            Err(crate::api::error::AppError(e.into()))
        }
    }
}
