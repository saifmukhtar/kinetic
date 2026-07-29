//! League of Entropy Drand Quicknet randomness beacon client and cache manager.
//!
//! Fetches 3-second public randomness pulses from Drand HTTP endpoints and DNS seed TXT records,
//! verifies BLS12-381 G2 signatures, binds SHA-256 randomness output, and caches valid pulses to storage.
//!
//! ## Pulse Acquisition Strategy
//!
//! 1. Try each HTTP endpoint (from `config.toml` and DNS TXT records) with up to 3 attempts and 500ms/1s/2s backoff.
//! 2. For each successful response: verify BLS signature + SHA-256 binding + staleness (≤200 rounds / 10 minutes).
//! 3. If all endpoints fail: fall back to local storage cache (may be stale but still usable for heartbeats).
//! 4. If no cache exists: return `DrandError::NoCachedPulse` (`KIN-DRA-004`).
//!
//! ## Dev Mode Behavior
//!
//! In dev mode ([`is_dev_mode()`](crate::config::is_dev_mode)), all signature verification is bypassed
//! and a synthetic mock pulse with `round: 5,000,000` is returned if no cache exists.

use crate::error::DrandError;
use crate::traits::StorageEngine;
use drand_verify::{G2PubkeyRfc, Pubkey};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::warn;
use web_time::Duration;

#[cfg(not(target_arch = "wasm32"))]
use hickory_resolver::config::*;

// Heartbeat staleness threshold — 10 minutes in Drand Quicknet rounds (3s each)
const MAX_STALE_ROUNDS_FOR_HEARTBEAT: u64 = 200; // 10min * 20 rounds/min

/// A single randomness beacon pulse from the drand Quicknet network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DrandPulse {
    /// Monotonically increasing round number.
    pub round: u64,
    /// Hex-encoded SHA-256 randomness output string.
    pub randomness: String,
    /// BLS12-381 G2 signature string from the League of Entropy.
    #[serde(default)]
    pub signature: String,
    /// `true` if loaded from the local storage cache rather than fetched live.
    #[serde(default)]
    pub is_from_cache: bool,
    /// `true` if no live or cached pulse was available (sentinel unavailable state).
    #[serde(default)]
    pub is_unavailable: bool,
}

impl DrandPulse {
    /// Returns a sentinel [`DrandPulse`] representing an unavailable beacon state.
    pub fn unavailable() -> Self {
        Self {
            round: 0,
            randomness: String::new(),
            signature: String::new(),
            is_from_cache: false,
            is_unavailable: true,
        }
    }

    /// Returns `true` if this pulse is suitable for driving VDF domain registrations (must be live).
    pub fn is_usable_for_registration(&self) -> bool {
        !self.is_unavailable && !self.is_from_cache
    }

    /// Returns `true` if this pulse is acceptable for heartbeat validation.
    ///
    /// Accepts cached pulses if their round age relative to `current_live_round` does not
    /// exceed `MAX_STALE_ROUNDS_FOR_HEARTBEAT` (200 rounds / 10 minutes).
    pub fn is_usable_for_heartbeat(&self, current_live_round: u64) -> bool {
        if self.is_unavailable {
            return false;
        }
        if !self.is_from_cache {
            return true;
        }
        let staleness = current_live_round.saturating_sub(self.round);
        staleness <= MAX_STALE_ROUNDS_FOR_HEARTBEAT
    }

    /// Cryptographically verifies the pulse against the League of Entropy Quicknet public key.
    ///
    /// Validates both the BLS12-381 G2 signature and the `SHA-256(signature) == randomness` binding.
    /// In dev mode (`is_dev_mode()`), bypasses signature verification to allow offline mock testing.
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

/// HTTP and DNS-backed client for fetching and caching Drand Quicknet randomness pulses.
pub struct DrandClient {
    http: reqwest::Client,
    storage: Option<Arc<dyn StorageEngine>>,
    endpoints: Vec<String>,
    drand_domain: Vec<String>,
    #[cfg(not(target_arch = "wasm32"))]
    resolver: hickory_resolver::TokioAsyncResolver,
}

impl DrandClient {
    /// Creates a new [`DrandClient`].
    ///
    /// Accepts an optional [`StorageEngine`] handle to cache successfully fetched pulses on disk.
    pub fn new(storage: Option<Arc<dyn StorageEngine>>) -> Self {
        let config = crate::config::KineticConfig::load();
        Self {
            http: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap_or_default(),
            storage,
            endpoints: config.drand.endpoints,
            drand_domain: config.drand.drand_domain,
            #[cfg(not(target_arch = "wasm32"))]
            resolver: hickory_resolver::TokioAsyncResolver::tokio(
                ResolverConfig::default(),
                ResolverOpts::default(),
            ),
        }
    }

    /// Fetches the latest verified Drand pulse across configured endpoints and DNS seeds.
    ///
    /// Performs exponential backoff, verifies BLS signatures, enforces a 10-minute staleness
    /// limit, and falls back to local storage cache if network endpoints are unreachable.
    ///
    /// # Errors
    ///
    /// - Returns [`DrandError::InvalidSignature`](crate::error::DrandError::InvalidSignature) if an endpoint returns a bad BLS signature.
    /// - Returns [`DrandError::StalePulse`](crate::error::DrandError::StalePulse) if a pulse is older than 200 rounds (10 minutes).
    /// - Returns [`DrandError::HttpError`](crate::error::DrandError::HttpError) on non-200 HTTP responses.
    /// - Returns [`DrandError::Network`](crate::error::DrandError::Network) on connection timeouts or body size limit violations (> 64 KB).
    /// - Returns [`DrandError::NoCachedPulse`](crate::error::DrandError::NoCachedPulse) if all endpoints fail and no cache exists.
    /// - Returns [`DrandError::AllEndpointsFailed`](crate::error::DrandError::AllEndpointsFailed) if network and fallback attempts fail.
    pub async fn fetch_latest(&self) -> Result<DrandPulse, DrandError> {
        if crate::config::is_dev_mode() {
            return self.load_cached_pulse();
        }

        let mut endpoints = self.endpoints.clone();

        #[cfg(not(target_arch = "wasm32"))]
        {
            let mut injected_count = 0;
            for domain in &self.drand_domain {
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
                    let estimated_round = (now
                        .saturating_sub(crate::constants::DRAND_GENESIS_TIME))
                        / crate::constants::DRAND_PERIOD;
                    let age = estimated_round.saturating_sub(pulse.round);

                    if age > MAX_STALE_ROUNDS_FOR_HEARTBEAT {
                        warn!(
                            "Drand endpoint {} returned an unacceptably stale pulse (round {}, expected ~{}).",
                            endpoint, pulse.round, estimated_round
                        );
                        last_error = Some(DrandError::StalePulse {
                            expected: estimated_round,
                            got: pulse.round,
                        });
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

    /// Attempts to fetch a single Drand pulse from a URL with up to 3 attempts and exponential backoff.
    ///
    /// Attempt delays: 500ms → 1s → 2s. Per-request HTTP timeout: 5 seconds.
    /// Response body size is capped at 64 KB to prevent memory exhaustion from malicious endpoints.
    ///
    /// This is a `pub(crate)` helper called by [`fetch_latest`](Self::fetch_latest).
    ///
    /// # Errors
    ///
    /// - Returns [`DrandError::HttpError`] (`KIN-DRA-002`) if the final attempt returns a non-2xx HTTP status.
    /// - Returns [`DrandError::Network`] (`KIN-DRA-003`) on connection failure or response body exceeds 64 KB.
    /// - Returns [`DrandError::JsonError`] (`KIN-DRA-006`) if the response body fails JSON deserialization.
    /// - Returns [`DrandError::AllEndpointsFailed`] (`KIN-DRA-005`) if all 3 attempts are exhausted without success.
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
                        let bytes = resp
                            .bytes()
                            .await
                            .map_err(|e| DrandError::Network(e.to_string()))?;
                        if bytes.len() > 64 * 1024 {
                            return Err(DrandError::Network(
                                "Drand response exceeded 64 KB limit".to_string(),
                            ));
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

    /// Caches a verified pulse to the local storage engine.
    ///
    /// # Errors
    ///
    /// - Returns `JsonError` if JSON serialization fails.
    /// - Returns [`crate::error::DrandError::Storage`] if writing to disk fails.
    pub fn cache_pulse(&self, pulse: &DrandPulse) -> Result<(), DrandError> {
        if let Some(storage) = &self.storage {
            let bytes = serde_json::to_vec(pulse)?;
            storage.put(crate::constants::DB_PREFIX_LAST_DRAND, &bytes)?;
        }
        Ok(())
    }

    /// Retrieves the most recent successfully cached pulse from local storage.
    ///
    /// In dev mode (`is_dev_mode()`), if the cache is empty, returns a synthetic mock pulse (`round: 5,000,000`).
    ///
    /// # Errors
    ///
    /// - Returns [`DrandError::NoCachedPulse`](crate::error::DrandError::NoCachedPulse) if storage is empty or missing (outside dev mode).
    /// - Returns [`DrandError::Storage`](crate::error::DrandError::Storage) if database reading fails.
    pub fn load_cached_pulse(&self) -> Result<DrandPulse, DrandError> {
        if let Some(storage) = &self.storage {
            if let Ok(Some(bytes)) = storage.get(crate::constants::DB_PREFIX_LAST_DRAND) {
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

        // Should fail cryptographic verification (unless in dev mode, which always passes)
        if crate::config::is_dev_mode() {
            assert!(pulse.verify(), "Dev mode should always pass verification");
        } else {
            assert!(
                !pulse.verify(),
                "Invalid Quicknet pulse incorrectly passed BLS verification"
            );
        }
    }
}
