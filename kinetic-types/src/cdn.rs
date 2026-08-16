//! High-performance IPC proxy payloads for CDN caching layer.
//!
//! Provides zero-copy, reference-counted request and response structures ([`CdnRequest`],
//! [`CdnResponse`]) used for serving NameRecords from DHT node caches directly.

use serde::{Deserialize, Serialize};

/// CDN request payload to resolve a .kin name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CdnRequest {
    /// Request target name (e.g., `mysite.kin`).
    pub name: std::sync::Arc<str>,
}

/// CDN response payload returning a cached NameRecord.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CdnResponse {
    /// Serialized NameRecord, if found in the cache.
    pub record: Option<Vec<u8>>,
}
