//! DNS caching layer for the Kinetic Proxy.

use std::time::{Instant, Duration};
use lru::LruCache;
use std::num::NonZeroUsize;

/// An LRU cache for DNS resolution to speed up web proxy requests.
pub struct DnsCache {
    cache: LruCache<String, (Vec<u8>, Instant)>,
    ttl: Duration,
}

impl DnsCache {
    /// Creates a new DNS Cache.
    pub fn new(capacity: usize, ttl_seconds: u64) -> Self {
        Self {
            cache: LruCache::new(NonZeroUsize::new(capacity).unwrap_or(NonZeroUsize::new(100).unwrap())),
            ttl: Duration::from_secs(ttl_seconds),
        }
    }

    /// Gets a cached resolution payload if it exists and has not expired.
    pub fn get(&mut self, name: &str) -> Option<Vec<u8>> {
        if let Some((payload, timestamp)) = self.cache.get(name) {
            if timestamp.elapsed() <= self.ttl {
                return Some(payload.clone());
            }
        }
        None
    }

    /// Inserts a resolved payload into the cache.
    pub fn insert(&mut self, name: String, payload: Vec<u8>) {
        self.cache.put(name, (payload, Instant::now()));
    }

    /// Flushes all entries from the cache.
    pub fn flush(&mut self) {
        self.cache.clear();
    }
}
