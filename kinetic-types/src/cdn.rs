//! High-performance IPC proxy payloads for CDN caching layer.
//!
//! Provides zero-copy, reference-counted request and response structures ([`CdnRequest`],
//! [`CdnResponse`]) used for serving NameRecords from DHT node caches directly.

use serde::{Deserialize, Serialize};

/// CDN request payload to resolve a domain name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CdnRequest {
    /// Request target domain name (e.g., `mysite.kin`).
    pub domain: std::sync::Arc<str>,
}

/// CDN response payload returning a cached NameRecord.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CdnResponse {
    /// Serialized NameRecord, if found in the cache.
    pub record: Option<Vec<u8>>,
}
