use kinetic_core::drand::RawKyn;
use kinetic_core::error::KynProviderError;
use kinetic_core::traits::{KynProvider, StorageEngine};
use std::sync::Arc;
use tracing::warn;
use web_time::Duration;

#[cfg(not(target_arch = "wasm32"))]
use hickory_resolver::config::*;

const MAX_STALE_ROUNDS_FOR_HEARTBEAT: u64 = 200;

/// HTTP and DNS-backed client for fetching and caching Drand Quicknet randomness kyns.
pub struct DrandProvider {
    http: reqwest::Client,
    storage: Option<Arc<dyn StorageEngine>>,
    endpoints: Vec<String>,
    drand_domain: Vec<String>,
    #[cfg(not(target_arch = "wasm32"))]
    resolver: hickory_resolver::TokioAsyncResolver,
}

impl DrandProvider {
    /// Creates a new [`DrandProvider`].
    ///
    /// Accepts an optional [`StorageEngine`] handle to cache successfully fetched kyns on disk.
    pub fn new(storage: Option<Arc<dyn StorageEngine>>) -> Self {
        let config = kinetic_local::config::load_config();
        Self {
            #[cfg(not(target_arch = "wasm32"))]
            http: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap_or_default(),
            #[cfg(target_arch = "wasm32")]
            http: reqwest::Client::new(),
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

    /// Attempts to fetch a specific drand url with automatic exponential backoff.
    ///
    /// Makes up to 3 attempts (initial + 2 retries). Delay starts at 500ms and doubles
    /// after each failure (1000ms, 2000ms). Connection timeouts are set to 5 seconds.
    ///
    /// Response body size is capped at 64 KB to prevent memory exhaustion from malicious endpoints.
    ///
    /// This is a `pub(crate)` helper called by [`fetch_latest`](Self::fetch_latest).
    ///
    /// # Errors
    ///
    /// - Returns [`KynProviderError::ResponseTooLarge`] (`KIN-RND-011`) if the payload exceeds 64 KB.
    /// - Returns [`KynProviderError::StreamReadFailed`] (`KIN-RND-010`) if reading the network stream fails.
    /// - Returns [`KynProviderError::Serde`] (`KIN-RND-005`) if the response body fails JSON deserialization.
    /// - Returns [`KynProviderError::AllEndpointsFailed`] (`KIN-RND-001`) if all 3 attempts are exhausted without success.
    async fn fetch_with_backoff(&self, url: &str) -> Result<RawKyn, KynProviderError> {
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
                            .map_err(|e| KynProviderError::HttpClient(e.to_string()))?;
                        if bytes.len() > kinetic_core::constants::LIMITS_DRAND_MAX_RESPONSE_BYTES {
                            return Err(KynProviderError::ResponseTooLarge(bytes.len()));
                        }
                        return Ok(serde_json::from_slice::<RawKyn>(&bytes)?);
                    }
                    #[cfg(not(target_arch = "wasm32"))]
                    {
                        let mut body = bytes::BytesMut::new();
                        while let Some(chunk) = resp
                            .chunk()
                            .await
                            .map_err(|e| KynProviderError::StreamReadFailed(e.to_string()))?
                        {
                            body.extend_from_slice(&chunk);
                            if body.len() > kinetic_core::constants::LIMITS_DRAND_MAX_RESPONSE_BYTES
                            {
                                return Err(KynProviderError::ResponseTooLarge(body.len()));
                            }
                        }
                        return Ok(serde_json::from_slice::<RawKyn>(&body)?);
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
                    return Err(KynProviderError::HttpError(resp.status().as_u16()));
                }
                Err(_) if attempt < max_attempts - 1 => {
                    #[cfg(not(target_arch = "wasm32"))]
                    tokio::time::sleep(delay).await;
                    #[cfg(target_arch = "wasm32")]
                    gloo_timers::future::sleep(delay).await;
                    delay *= 2; // exponential backoff
                }
                Err(e) => return Err(KynProviderError::HttpClient(e.to_string())),
            }
        }
        Err(KynProviderError::AllEndpointsFailed)
    }
}

#[async_trait::async_trait]
impl KynProvider for DrandProvider {
    /// Fetches the latest available kyn by racing HTTP endpoints and DNS records.
    ///
    /// # Errors
    ///
    /// - Returns [`KynProviderError::InvalidSignature`](crate::error::KynProviderError::InvalidSignature) if an endpoint returns a bad BLS signature.
    /// - Returns [`KynProviderError::StaleKyn`](crate::error::KynProviderError::StaleKyn) if a kyn is older than 200 kyns (10 minutes).
    /// - Returns [`KynProviderError::HttpError`](crate::error::KynProviderError::HttpError) on non-200 HTTP responses.
    /// - Returns [`KynProviderError::StreamReadFailed`](crate::error::KynProviderError::StreamReadFailed) on connection timeouts or stream errors.
    /// - Returns [`KynProviderError::ResponseTooLarge`](crate::error::KynProviderError::ResponseTooLarge) on body size limit violations (> 64 KB).
    /// - Returns [`KynProviderError::NoCachedKyn`](crate::error::KynProviderError::NoCachedKyn) if all endpoints fail and no cache exists.
    /// - Returns [`KynProviderError::AllEndpointsFailed`](crate::error::KynProviderError::AllEndpointsFailed) if network and fallback attempts fail.
    async fn fetch_latest(&self) -> Result<RawKyn, KynProviderError> {
        if kinetic_core::config::is_dev_mode() {
            return self.load_cached_kyn();
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

        for endpoint in &endpoints {
            match self.fetch_with_backoff(endpoint).await {
                Ok(mut kyn) => {
                    if !kyn.verify() {
                        let err = KynProviderError::InvalidSignature;
                        warn!(
                            "{}: Drand endpoint {} returned a cryptographically invalid kyn!",
                            err.code(),
                            endpoint
                        );
                        continue;
                    }

                    let now = web_time::SystemTime::now()
                        .duration_since(web_time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    let estimated_kyn = (now
                        .saturating_sub(kinetic_core::constants::DRAND_GENESIS_TIME))
                        / kinetic_core::constants::DRAND_PERIOD;
                    let age = estimated_kyn.saturating_sub(kyn.kyn);

                    if age > MAX_STALE_ROUNDS_FOR_HEARTBEAT {
                        let err = KynProviderError::StaleKyn {
                            expected: estimated_kyn,
                            got: kyn.kyn,
                        };
                        warn!(
                            "{}: Drand endpoint {} returned an unacceptably stale kyn (kyn {}, expected ~{}).",
                            err.code(),
                            endpoint,
                            kyn.kyn,
                            estimated_kyn
                        );
                        continue;
                    }

                    kyn.is_from_cache = false;
                    kyn.is_unavailable = false;

                    let _ = self.cache_kyn(&kyn);
                    return Ok(kyn);
                }
                Err(e) => {
                    warn!("Failed to fetch kyn from endpoint {}: {}", endpoint, e);
                    continue;
                }
            }
        }

        warn!("All drand live endpoints failed. Attempting to fall back to cached kyn.");
        match self.load_cached_kyn() {
            Ok(kyn) => {
                let err = KynProviderError::LiveFetchFailedFallback;
                warn!(error_code = err.code(), "{}", err);
                Ok(kyn)
            }
            Err(_) => Err(KynProviderError::AllEndpointsFailed),
        }
    }

    fn cache_kyn(&self, kyn: &RawKyn) -> Result<(), KynProviderError> {
        if let Some(storage) = &self.storage
            && let Ok(bytes) = serde_json::to_vec(kyn)
        {
            storage
                .put(kinetic_core::constants::DB_PREFIX_LAST_DRAND, &bytes)
                .map_err(KynProviderError::Storage)?;
        }
        Ok(())
    }

    fn load_cached_kyn(&self) -> Result<RawKyn, KynProviderError> {
        if let Some(storage) = &self.storage
            && let Some(bytes) = storage
                .get(kinetic_core::constants::DB_PREFIX_LAST_DRAND)
                .map_err(KynProviderError::Storage)?
            && let Ok(mut kyn) = serde_json::from_slice::<RawKyn>(&bytes)
        {
            kyn.is_from_cache = true;
            return Ok(kyn);
        }

        if kinetic_core::config::is_dev_mode() {
            let err = KynProviderError::DevModeMockKyn;
            tracing::warn!(error_code = err.code(), "{}", err);
            return Ok(RawKyn {
                kyn: 5000000,
                randomness: "mock_randomness".to_string(),
                signature: String::new(),
                is_from_cache: true,
                is_unavailable: false,
            });
        }

        Err(KynProviderError::NoCachedKyn)
    }
}
