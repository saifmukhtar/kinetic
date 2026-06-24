use serde::{Serialize, Deserialize};
use std::time::Duration;
use tracing::warn;
use std::sync::Arc;
use kinetic_storage::SledStorage;
use kinetic_core::traits::StorageEngine;
use kinetic_core::KineticError;
use thiserror::Error;

const DRAND_ENDPOINTS: &[&str] = &[
    "https://api.drand.sh/52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971/public/latest",
    "https://drand.cloudflare.com/52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971/public/latest", 
    "https://api2.drand.sh/52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971/public/latest",
    "https://api3.drand.sh/52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971/public/latest",
];

const CACHE_KEY: &str = "drand_last_pulse";

// Heartbeat staleness threshold — 24 hours in Drand rounds (30s each)
const MAX_STALE_ROUNDS_FOR_HEARTBEAT: u64 = 2880; // 24hr * 60min * 2 rounds/min

#[derive(Error, Debug)]
pub enum DrandError {
    #[error("All Drand endpoints failed")]
    AllEndpointsFailed,
    #[error("Network error: {0}")]
    Network(String),
    #[error("HTTP status error: {0}")]
    HttpError(u16),
    #[error("No cached pulse found")]
    NoCachedPulse,
    #[error("Serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("Storage error: {0}")]
    Storage(#[from] KineticError),
    #[error("Reqwest error: {0}")]
    Reqwest(#[from] reqwest::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DrandPulse {
    pub round: u64,
    pub randomness: String,
    pub is_from_cache: bool,
    pub is_unavailable: bool,
}

impl DrandPulse {
    pub fn unavailable() -> Self {
        Self {
            round: 0,
            randomness: String::new(),
            is_from_cache: false,
            is_unavailable: true,
        }
    }
    
    pub fn is_usable_for_registration(&self) -> bool {
        !self.is_unavailable && !self.is_from_cache
    }
    
    pub fn is_usable_for_heartbeat(&self, current_live_round: u64) -> bool {
        if self.is_unavailable { return false; }
        if !self.is_from_cache { return true; }
        // Cached: only accept if not too stale
        let staleness = current_live_round.saturating_sub(self.round);
        staleness <= MAX_STALE_ROUNDS_FOR_HEARTBEAT
    }
}

pub struct DrandClient {
    http: reqwest::Client,
    storage: Arc<SledStorage>,
}

impl DrandClient {
    pub fn new(storage: Arc<SledStorage>) -> Self {
        Self {
            http: reqwest::Client::new(),
            storage,
        }
    }

    pub async fn fetch_latest(&self) -> Result<DrandPulse, DrandError> {
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
            match self.http.get(url)
                .timeout(Duration::from_secs(5))
                .send()
                .await
            {
                Ok(resp) if resp.status().is_success() => {
                    return Ok(resp.json::<DrandPulse>().await?);
                }
                Ok(_resp) if attempt < max_attempts - 1 => {
                    tokio::time::sleep(delay).await;
                    delay *= 2;
                }
                Ok(resp) => {
                    return Err(DrandError::HttpError(resp.status().as_u16()));
                }
                Err(_) if attempt < max_attempts - 1 => {
                    tokio::time::sleep(delay).await;
                    delay *= 2; // exponential backoff
                }
                Err(e) => return Err(DrandError::Network(e.to_string())),
            }
        }
        unreachable!()
    }

    fn cache_pulse(&self, pulse: &DrandPulse) -> Result<(), DrandError> {
        let bytes = serde_json::to_vec(pulse)?;
        self.storage.put(CACHE_KEY.as_bytes(), &bytes)?;
        Ok(())
    }

    pub fn load_cached_pulse(&self) -> Result<DrandPulse, DrandError> {
        let bytes = self.storage.get(CACHE_KEY.as_bytes())?
            .ok_or(DrandError::NoCachedPulse)?;
        let mut pulse: DrandPulse = serde_json::from_slice(&bytes)?;
        pulse.is_from_cache = true;
        Ok(pulse)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use httptest::{Server, Expectation, matchers::*, responders::*};
    use kinetic_storage::SledStorage;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_fetch_with_backoff_success() {
        let server = Server::run();
        server.expect(
            Expectation::matching(request::method_path("GET", "/public/latest"))
                .times(1)
                .respond_with(json_encoded(serde_json::json!({
                    "round": 100,
                    "randomness": "abc",
                    "is_from_cache": false,
                    "is_unavailable": false
                }))),
        );

        let url = server.url("/public/latest");
        let dir = tempdir().unwrap();
        let storage = Arc::new(SledStorage::new(dir.path().to_str().unwrap()).unwrap());
        let client = DrandClient::new(storage);
        
        let pulse = client.fetch_with_backoff(&url.to_string()).await.unwrap();
        assert_eq!(pulse.round, 100);
    }

    #[tokio::test]
    async fn test_fetch_with_backoff_retries() {
        let server = Server::run();
        use std::sync::atomic::{AtomicUsize, Ordering};
        let attempts = Arc::new(AtomicUsize::new(0));
        
        server.expect(
            Expectation::matching(request::method_path("GET", "/public/latest"))
                .times(3)
                .respond_with(move || {
                    if attempts.fetch_add(1, Ordering::SeqCst) < 2 {
                        http::Response::builder().status(500).body(Vec::new()).unwrap()
                    } else {
                        let json = serde_json::json!({
                            "round": 101,
                            "randomness": "def",
                            "is_from_cache": false,
                            "is_unavailable": false
                        });
                        http::Response::builder()
                            .status(200)
                            .body(serde_json::to_vec(&json).unwrap())
                            .unwrap()
                    }
                }),
        );

        let url = server.url("/public/latest");
        let dir = tempdir().unwrap();
        let storage = Arc::new(SledStorage::new(dir.path().to_str().unwrap()).unwrap());
        let client = DrandClient::new(storage);
        
        let pulse = client.fetch_with_backoff(&url.to_string()).await.unwrap();
        assert_eq!(pulse.round, 101);
    }

    #[tokio::test]
    async fn test_fetch_with_backoff_failure() {
        let server = Server::run();
        server.expect(
            Expectation::matching(request::method_path("GET", "/public/latest"))
                .times(3)
                .respond_with(status_code(500)),
        );

        let url = server.url("/public/latest");
        let dir = tempdir().unwrap();
        let storage = Arc::new(SledStorage::new(dir.path().to_str().unwrap()).unwrap());
        let client = DrandClient::new(storage);
        
        let res = client.fetch_with_backoff(&url.to_string()).await;
        assert!(res.is_err());
    }
}
