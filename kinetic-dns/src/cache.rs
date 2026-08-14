//! Asymmetric TTL cache configuration and eviction policies for DNS responses.

use moka::Expiry;
use moka::future::Cache;
use std::time::{Duration, Instant};

/// Custom cache expiry logic for DNS records.
/// Assigns asymmetric TTLs: 5 minutes for positive hits, 30 seconds for negative hits.
pub struct KineticExpiry;

impl Expiry<String, Option<Vec<u8>>> for KineticExpiry {
    fn expire_after_create(
        &self,
        _key: &String,
        value: &Option<Vec<u8>>,
        _created_at: Instant,
    ) -> Option<Duration> {
        if value.is_some() {
            Some(Duration::from_secs(300)) // 5 minutes positive cache
        } else {
            Some(Duration::from_secs(30)) // 30 seconds negative cache (NXDOMAIN)
        }
    }

    fn expire_after_read(
        &self,
        _key: &String,
        _value: &Option<Vec<u8>>,
        _read_at: Instant,
        duration_until_expiry: Option<Duration>,
        _last_modified_at: Instant,
    ) -> Option<Duration> {
        duration_until_expiry // Do not extend TTL on read
    }

    fn expire_after_update(
        &self,
        _key: &String,
        value: &Option<Vec<u8>>,
        _updated_at: Instant,
        _duration_until_expiry: Option<Duration>,
    ) -> Option<Duration> {
        if value.is_some() {
            Some(Duration::from_secs(300))
        } else {
            Some(Duration::from_secs(30))
        }
    }
}

/// Creates a new Moka cache for DNS resolution results.
pub fn create_cache() -> Cache<String, Option<Vec<u8>>> {
    Cache::builder()
        .expire_after(KineticExpiry)
        .max_capacity(10 * 1024 * 1024) // 10 MB total memory limit
        .weigher(|_key, value: &Option<Vec<u8>>| -> u32 {
            value.as_ref().map(|v| v.len() as u32).unwrap_or(1)
        })
        .build()
}
