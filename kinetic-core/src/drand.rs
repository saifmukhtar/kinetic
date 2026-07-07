use crate::traits::StorageEngine;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use web_time::Duration;
use thiserror::Error;
use tracing::warn;

/// The set of drand Quicknet HTTP endpoints tried in order.
///
/// The chain hash `52db9ba7…` identifies the Quicknet chain (3-second round period).
pub const DRAND_ENDPOINTS: &[&str] = &[
    "https://api.drand.sh/52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971/public/latest",
    "https://drand.cloudflare.com/52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971/public/latest",
    "https://api2.drand.sh/52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971/public/latest",
    "https://api3.drand.sh/52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971/public/latest",
];

/// Unix timestamp of the Quicknet chain's genesis (2023-08-23).
pub const QUICKNET_GENESIS_TIME: u64 = 1692803367;
/// Duration in seconds of each Quicknet round.
pub const QUICKNET_PERIOD: u64 = 3;

const CACHE_KEY: &str = "drand_last_pulse";

// Heartbeat staleness threshold — 24 hours in Drand rounds (30s each)
const MAX_STALE_ROUNDS_FOR_HEARTBEAT: u64 = 2880; // 24hr * 60min * 2 rounds/min

/// Error type for drand beacon fetches and cache operations.
#[derive(Error, Debug)]
pub enum DrandError {
    /// All configured endpoints returned errors or timed out.
    #[error("All Drand endpoints failed")]
    AllEndpointsFailed,
    /// A network-level error (e.g. DNS failure, connection refused).
    #[error("Network error: {0}")]
    Network(String),
    /// An endpoint returned a non-2xx HTTP status.
    #[error("HTTP status error: {0}")]
    HttpError(u16),
    /// No pulse was found in the local cache (and the network is also unavailable).
    #[error("No cached pulse found")]
    NoCachedPulse,
    /// JSON (de)serialization failed.
    #[error("Serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    /// A storage engine error occurred while reading or writing the cache.
    #[error("Storage error: {0}")]
    Storage(#[from] crate::error::StorageError),
    /// An HTTP client error from the `reqwest` library.
    #[error("Reqwest error: {0}")]
    Reqwest(#[from] reqwest::Error),
}

/// A single randomness beacon from the drand Quicknet chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DrandPulse {
    /// The monotonically increasing round number.
    pub round: u64,
    /// The hex-encoded randomness output for this round.
    pub randomness: String,
    /// `true` if this pulse was loaded from the local Sled cache rather than fetched live.
    #[serde(default)]
    pub is_from_cache: bool,
    /// `true` if no live or cached pulse was available (sentinel / unavailable state).
    #[serde(default)]
    pub is_unavailable: bool,
}

impl DrandPulse {
    /// Returns a sentinel [`DrandPulse`] representing an unavailable beacon.
    pub fn unavailable() -> Self {
        Self {
            round: 0,
            randomness: String::new(),
            is_from_cache: false,
            is_unavailable: true,
        }
    }

    /// Returns `true` if this pulse is suitable for driving a VDF-based registration
    /// (must be live — not from cache and not the unavailable sentinel).
    pub fn is_usable_for_registration(&self) -> bool {
        !self.is_unavailable && !self.is_from_cache
    }

    /// Returns `true` if this pulse can be used to validate a heartbeat.
    ///
    /// Cached pulses are accepted if they are not too stale relative to `current_live_round`
    /// (threshold: `MAX_STALE_ROUNDS_FOR_HEARTBEAT`).
    pub fn is_usable_for_heartbeat(&self, current_live_round: u64) -> bool {
        if self.is_unavailable {
            return false;
        }
        if !self.is_from_cache {
            return true;
        }
        // Cached: only accept if not too stale
        let staleness = current_live_round.saturating_sub(self.round);
        staleness <= MAX_STALE_ROUNDS_FOR_HEARTBEAT
    }
}

/// HTTP client for the drand Quicknet randomness beacon.
///
/// Fetches the latest pulse from [`DRAND_ENDPOINTS`] with exponential backoff
/// and falls back to a locally cached pulse when the network is unavailable.
pub struct DrandClient {
    http: reqwest::Client,
    storage: Option<Arc<dyn StorageEngine>>,
}

impl DrandClient {
    /// Creates a new [`DrandClient`].
    ///
    /// Pass `Some(storage)` to enable caching of the last successfully fetched pulse.
    pub fn new(storage: Option<Arc<dyn StorageEngine>>) -> Self {
        Self {
            http: reqwest::Client::new(),
            storage,
        }
    }

    /// Fetches the latest drand pulse, falling back to the on-disk cache if all
    /// network endpoints fail.
    pub async fn fetch_latest(&self) -> Result<DrandPulse, DrandError> {
        if crate::config::is_dev_mode() {
            return self.load_cached_pulse();
        }

        // Try each endpoint with exponential backoff
        let mut last_error = None;

        for endpoint in DRAND_ENDPOINTS {
            match self.fetch_with_backoff(endpoint).await {
                Ok(mut pulse) => {
                    pulse.is_from_cache = false;
                    pulse.is_unavailable = false;
                    // Cache on every successful fetch
                    let _ = self.cache_pulse(&pulse);
                    return Ok(pulse);
                }
                Err(e) => {
                    warn!("Drand endpoint {} unreachable: {}", endpoint, e);
                    last_error = Some(e);
                }
            }
        }

        // All endpoints failed — try cache
        warn!("All Drand endpoints unreachable — falling back to cached pulse");
        self.load_cached_pulse()
            .map_err(|_| last_error.unwrap_or(DrandError::AllEndpointsFailed))
    }

    async fn fetch_with_backoff(&self, url: &str) -> Result<DrandPulse, DrandError> {
        let mut delay = Duration::from_millis(500);
        let max_attempts = 3;

        for attempt in 0..max_attempts {
            match self
                .http
                .get(url)
                .timeout(Duration::from_secs(5))
                .send()
                .await
            {
                Ok(resp) if resp.status().is_success() => {
                    return Ok(resp.json::<DrandPulse>().await?);
                }
                Ok(_resp) if attempt < max_attempts - 1 => {
                    #[cfg(not(target_arch = "wasm32"))]
                    tokio::time::sleep(delay).await;
                    #[cfg(target_arch = "wasm32")]
                    let _ = delay; // TODO: Sleep in wasm
                    delay *= 2;
                }
                Ok(resp) => {
                    return Err(DrandError::HttpError(resp.status().as_u16()));
                }
                Err(_) if attempt < max_attempts - 1 => {
                    #[cfg(not(target_arch = "wasm32"))]
                    tokio::time::sleep(delay).await;
                    #[cfg(target_arch = "wasm32")]
                    let _ = delay; // TODO: Sleep in wasm
                    delay *= 2; // exponential backoff
                }
                Err(e) => return Err(DrandError::Network(e.to_string())),
            }
        }
        Err(DrandError::AllEndpointsFailed)
    }

    fn cache_pulse(&self, pulse: &DrandPulse) -> Result<(), DrandError> {
        if let Some(storage) = &self.storage {
            let bytes = serde_json::to_vec(pulse)?;
            storage.put(CACHE_KEY.as_bytes(), &bytes)?;
        }
        Ok(())
    }

    /// Retrieves the most recent successfully fetched pulse from local storage.
    ///
    /// In dev mode, returns a synthetic mock pulse to allow offline development.
    /// When storage is empty and the system clock is available, returns an
    /// estimated pulse derived from the Quicknet genesis time.
    pub fn load_cached_pulse(&self) -> Result<DrandPulse, DrandError> {
        if let Some(storage) = &self.storage {
            if let Ok(Some(bytes)) = storage.get(CACHE_KEY.as_bytes()) {
                if let Ok(mut pulse) = serde_json::from_slice::<DrandPulse>(&bytes) {
                    pulse.is_from_cache = true;
                    return Ok(pulse);
                }
            }
        }

        if crate::config::is_dev_mode() {
            tracing::warn!("DEV MODE: Returning mock drand pulse because cache is empty.");
            return Ok(DrandPulse {
                round: 5000000,
                randomness: "mock_randomness".to_string(),
                is_from_cache: true,
                is_unavailable: false,
            });
        }

        // Offline Fallback for Quicknet
        if let Ok(now) = web_time::SystemTime::now().duration_since(web_time::UNIX_EPOCH) {
            if now.as_secs() > QUICKNET_GENESIS_TIME {
                let estimated_round = (now.as_secs() - QUICKNET_GENESIS_TIME) / QUICKNET_PERIOD;
                tracing::warn!(
                    "No drand cache found. Using offline estimated round: {}",
                    estimated_round
                );
                return Ok(DrandPulse {
                    round: estimated_round,
                    randomness: String::new(),
                    is_from_cache: true,
                    is_unavailable: false,
                });
            }
        }

        Err(DrandError::NoCachedPulse)
    }
}
