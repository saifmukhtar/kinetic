use crate::traits::StorageEngine;
use drand_verify::{G2PubkeyRfc, Pubkey};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::warn;
use web_time::Duration;

#[cfg(not(target_arch = "wasm32"))]
use hickory_resolver::config::*;

const CACHE_KEY: &str = "drand_last_pulse";

// Heartbeat staleness threshold — 10 minutes in Drand Quicknet rounds (3s each)
const MAX_STALE_ROUNDS_FOR_HEARTBEAT: u64 = 200; // 10min * 20 rounds/min

use crate::error::DrandError;

/// A single randomness beacon from the drand Quicknet chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DrandPulse {
    /// The monotonically increasing round number.
    pub round: u64,
    /// The hex-encoded randomness output for this round.
    pub randomness: String,
    /// The BLS signature from the League of Entropy.
    #[serde(default)]
    pub signature: String,
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
            signature: String::new(),
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
        // Cached: only accept if not too stale
        let staleness = current_live_round.saturating_sub(self.round);
        staleness <= MAX_STALE_ROUNDS_FOR_HEARTBEAT
    }

    /// Cryptographically verifies the pulse against the League of Entropy's public key.
    pub fn verify(&self) -> bool {
        if self.is_unavailable {
            return true;
        }

        if crate::config::is_dev_mode() {
            // Dev mode uses mock_randomness without a valid signature.
            return true;
        }

        let pubkey_bytes: [u8; 96] = match hex::decode(crate::constants::DRAND_PUBLIC_KEY)
            .ok()
            .and_then(|b| b.try_into().ok())
        {
            Some(b) => b,
            None => return false,
        };

        let pk = match G2PubkeyRfc::from_fixed(pubkey_bytes) {
            Ok(p) => p,
            Err(_) => return false,
        };

        let sig_bytes = match hex::decode(&self.signature) {
            Ok(b) => b,
            Err(_) => return false,
        };

        // 1. Verify BLS signature over the round (Quicknet is unchained, so previous_signature is empty array)
        if !pk.verify(self.round, &[], &sig_bytes).unwrap_or(false) {
            return false;
        }

        // 2. Bind the randomness to the signature: randomness MUST equal SHA-256(signature).
        use sha2::{Digest, Sha256};
        let expected = Sha256::digest(&sig_bytes);
        match hex::decode(&self.randomness) {
            Ok(r) => r.as_slice() == expected.as_slice(),
            Err(_) => false,
        }
    }
}

/// HTTP client for the drand Quicknet randomness beacon.
///
/// Fetches the latest pulse from `DRAND_ENDPOINTS` with exponential backoff
/// and falls back to a locally cached pulse when the network is unavailable.
pub struct DrandClient {
    http: reqwest::Client,
    storage: Option<Arc<dyn StorageEngine>>,
    endpoints: Vec<String>,
    seed_domains: Vec<String>,
    #[cfg(not(target_arch = "wasm32"))]
    resolver: hickory_resolver::TokioAsyncResolver,
}

impl DrandClient {
    /// Creates a new [`DrandClient`].
    ///
    /// Pass `Some(storage)` to enable caching of the last successfully fetched pulse.
    pub fn new(storage: Option<Arc<dyn StorageEngine>>) -> Self {
        let config = crate::config::KineticConfig::load();
        Self {
            http: reqwest::Client::new(),
            storage,
            endpoints: config.drand.endpoints,
            seed_domains: config.drand.seed_domains,
            #[cfg(not(target_arch = "wasm32"))]
            resolver: hickory_resolver::TokioAsyncResolver::tokio(
                ResolverConfig::default(),
                ResolverOpts::default(),
            ),
        }
    }

    /// Fetches the latest drand pulse, falling back to the on-disk cache if all
    /// network endpoints fail.
    pub async fn fetch_latest(&self) -> Result<DrandPulse, DrandError> {
        if crate::config::is_dev_mode() {
            return self.load_cached_pulse();
        }

        let mut endpoints = self.endpoints.clone();

        #[cfg(not(target_arch = "wasm32"))]
        {
            let mut injected_count = 0;
            for domain in &self.seed_domains {
                if injected_count >= 5 {
                    break;
                }
                if let Ok(txt_lookup) = self.resolver.txt_lookup(domain.as_str()).await {
                    for txt in txt_lookup.iter() {
                        if injected_count >= 5 {
                            break;
                        }
                        let url_str = txt.to_string();
                        let url_str = url_str.trim_matches('"').to_string();
                        if url_str.starts_with("https://") {
                            endpoints.push(url_str);
                            injected_count += 1;
                        }
                    }
                }
            }
        }

        // Try each endpoint with exponential backoff
        let mut last_error = None;

        for endpoint in &endpoints {
            match self.fetch_with_backoff(endpoint).await {
                Ok(mut pulse) => {
                    if !pulse.verify() {
                        warn!(
                            "Drand endpoint {} returned a cryptographically invalid pulse!",
                            endpoint
                        );
                        last_error = Some(DrandError::InvalidSignature);
                        continue;
                    }

                    let now = web_time::SystemTime::now()
                        .duration_since(web_time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    let estimated_round = (now.saturating_sub(crate::constants::DRAND_GENESIS_TIME)) / crate::constants::DRAND_PERIOD;
                    let age = estimated_round.saturating_sub(pulse.round);
                    
                    if age > MAX_STALE_ROUNDS_FOR_HEARTBEAT {
                        warn!(
                            "Drand endpoint {} returned an unacceptably stale pulse (round {}, expected ~{}).",
                            endpoint, pulse.round, estimated_round
                        );
                        last_error = Some(DrandError::StalePulse { expected: estimated_round, got: pulse.round });
                        continue;
                    }

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
                Ok(mut resp) if resp.status().is_success() => {
                    #[cfg(target_arch = "wasm32")]
                    {
                        let bytes = resp.bytes().await.map_err(|e| DrandError::Network(e.to_string()))?;
                        if bytes.len() > 64 * 1024 {
                            return Err(DrandError::Network("Drand response exceeded 64 KB limit".to_string()));
                        }
                        return Ok(serde_json::from_slice::<DrandPulse>(&bytes)?);
                    }
                    #[cfg(not(target_arch = "wasm32"))]
                    {
                        let mut body = bytes::BytesMut::new();
                        while let Some(chunk) = resp
                            .chunk()
                            .await
                            .map_err(|e| DrandError::Network(e.to_string()))?
                        {
                            body.extend_from_slice(&chunk);
                            if body.len() > 64 * 1024 {
                                return Err(DrandError::Network(
                                    "Drand response exceeded 64 KB limit".to_string(),
                                ));
                            }
                        }
                        return Ok(serde_json::from_slice::<DrandPulse>(&body)?);
                    }
                }
                Ok(_resp) if attempt < max_attempts - 1 => {
                    #[cfg(not(target_arch = "wasm32"))]
                    tokio::time::sleep(delay).await;
                    #[cfg(target_arch = "wasm32")]
                    gloo_timers::future::sleep(delay).await;
                    delay *= 2;
                }
                Ok(resp) => {
                    return Err(DrandError::HttpError(resp.status().as_u16()));
                }
                Err(_) if attempt < max_attempts - 1 => {
                    #[cfg(not(target_arch = "wasm32"))]
                    tokio::time::sleep(delay).await;
                    #[cfg(target_arch = "wasm32")]
                    gloo_timers::future::sleep(delay).await;
                    delay *= 2; // exponential backoff
                }
                Err(e) => return Err(DrandError::Network(e.to_string())),
            }
        }
        Err(DrandError::AllEndpointsFailed)
    }

    /// Caches a pulse to the local storage engine.
    pub fn cache_pulse(&self, pulse: &DrandPulse) -> Result<(), DrandError> {
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
                signature: String::new(),
                is_from_cache: true,
                is_unavailable: false,
            });
        }

        Err(DrandError::NoCachedPulse)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_quicknet_pulse_verification() {
        // Known valid pulse from Quicknet (Round 30290678)
        let pulse = DrandPulse {
            round: 30290678,
            randomness: "bd5f53ad61578f2566860e3792d01513b817e34c7de92f4781aa76b53ddef0ea".to_string(),
            signature: "ac8313d3ad1f95fe1b380ab6124aade0d4de5919fd60dc846746025ac9aa9d3c434b9dc94c0b75c4efd81aec9e2ef0b9".to_string(),
            is_from_cache: false,
            is_unavailable: false,
        };

        // Should cryptographically verify against QUICKNET_PUBLIC_KEY
        assert!(
            pulse.verify(),
            "Valid Quicknet pulse failed BLS verification"
        );
    }

    #[test]
    fn test_invalid_quicknet_pulse_verification() {
        // Corrupted pulse (tampered signature)
        let pulse = DrandPulse {
            round: 30290678,
            randomness: "bd5f53ad61578f2566860e3792d01513b817e34c7de92f4781aa76b53ddef0ea".to_string(),
            signature: "bc8313d3ad1f95fe1b380ab6124aade0d4de5919fd60dc846746025ac9aa9d3c434b9dc94c0b75c4efd81aec9e2ef0b9".to_string(), // flipped first char
            is_from_cache: false,
            is_unavailable: false,
        };

        // Should fail cryptographic verification
        assert!(
            !pulse.verify(),
            "Invalid Quicknet pulse incorrectly passed BLS verification"
        );
    }
}
