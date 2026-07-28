#![deny(missing_docs)]
//! # kinetic-dns
//!
//! DNS resolution layer for the Kinetic `.kin` naming network.
//!
//! This crate implements a custom DNS request handler ([`KineticDnsHandler`])
//! using the [hickory-dns](https://crates.io/crates/hickory-server) library.
//! It intercepts DNS queries for `.kin` domains, resolves them against the
//! Kinetic daemon's HTTP API (which in turn queries the Kademlia DHT), and
//! proxies all other queries to the host OS's native DNS configuration (with
//! a fallback to Cloudflare 1.1.1.1).
//!
//! ## Caching
//!
//! Resolved records are cached in-process using
//! [moka](https://crates.io/crates/moka) with asymmetric TTLs:
//!
//! - **Positive hits** (domain found): cached for 5 minutes.
//! - **Negative hits** (NXDOMAIN): cached for 30 seconds.
//!
//! Cache stampede protection is provided natively by moka's `try_get_with`.

pub mod cache;
pub mod handler;
pub mod kinetic_records;
pub mod upstream;

use hickory_resolver::TokioAsyncResolver;
use moka::future::Cache;
use std::collections::HashSet;
use std::sync::{Arc, RwLock};
use tracing::info;

/// The custom DNS handler that intercepts `.kin` queries and routes them to the DHT.
/// Standard queries (e.g., .com, .org) are passed through to upstream resolvers.
#[derive(Clone)]
pub struct KineticDnsHandler {
    /// URL of the Kinetic daemon REST API (e.g. `http://127.0.0.1:8080`).
    pub(crate) api_url: String,
    /// Shared HTTP client for querying the daemon REST API.
    pub(crate) http_client: reqwest::Client,
    /// Upstream TokioAsyncResolver instance for forwarding non-.kin queries.
    pub(crate) resolver: Arc<RwLock<TokioAsyncResolver>>,
    /// Asymmetric Moka cache storing DNS wire format responses.
    pub(crate) cache: Cache<String, Option<Vec<u8>>>,
    /// Set of foreign TLDs registered by the kinetic-atlas bridge.
    pub(crate) atlas_tlds: Arc<RwLock<HashSet<String>>>,
    /// Upstream TokioAsyncResolver specifically pointing to the local kinetic-atlas bridge.
    pub(crate) atlas_resolver: Arc<RwLock<TokioAsyncResolver>>,
}

impl KineticDnsHandler {
    /// Creates a new `KineticDnsHandler` with the specified API URL.
    ///
    /// This initializes the upstream DNS resolver, internal caches, and background tasks for config reloading.
    pub fn new(api_url: String, atlas_tlds: Arc<RwLock<HashSet<String>>>, atlas_port: u16) -> Self {
        let resolver = Arc::new(RwLock::new(upstream::create_resolver()));
        let atlas_resolver = Arc::new(RwLock::new(upstream::create_atlas_resolver(atlas_port)));
        let cache = cache::create_cache();

        let http_client = reqwest::Client::builder()
            .no_proxy()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap_or_else(|e| {
                tracing::warn!(
                    "Failed to build custom reqwest client ({}). Falling back to default",
                    e
                );
                reqwest::Client::new()
            });

        // Spawn a background task to hot-reload the OS DNS configuration every 5 minutes
        let resolver_clone = resolver.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
            loop {
                interval.tick().await;
                info!("Checking OS DNS configuration for updates...");
                let new_resolver = upstream::create_resolver();
                if let Ok(mut lock) = resolver_clone.write() {
                    *lock = new_resolver;
                }
            }
        });

        Self {
            api_url,
            http_client,
            resolver,
            cache,
            atlas_tlds,
            atlas_resolver,
        }
    }

    /// Explicitly invalidate the DNS cache for a given apex domain.
    /// This is called by the daemon after a successful local update to prevent serving stale data.
    pub async fn invalidate_cache(&self, apex_domain: &str) {
        let domain_normalized = kinetic_core::types::extract_apex_domain(apex_domain);
        self.cache.invalidate(&domain_normalized).await;
        tracing::info!(
            "Invalidated DNS cache for apex domain: {}",
            domain_normalized
        );
    }
}

#[cfg(test)]
mod tests;
