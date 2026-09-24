//! High-performance network payloads for the CDN caching layer.
//!
//! This module provides the zero-copy, reference-counted request and response
//! structures ([`CdnRequest`], [`CdnResponse`]) used for serving `NameEnvelope`s
//! directly from DHT node caches. By avoiding deep structural parsing during
//! cache hits, these payloads enable maximum throughput for the Kinetic Name
//! Resolution System (NRS).

use serde::{Deserialize, Serialize};

/// A network payload used by the CDN caching layer to request a specific `.kin` name.
///
/// This structure is designed for high-throughput environments where node caches
/// are heavily queried. It utilizes a reference-counted string (`Arc<str>`) to
/// enable zero-copy routing across multiple async tasks and channels without
/// triggering expensive heap allocations for every request.
///
/// # Examples
/// ```rust
/// use kinetic_types::cdn::CdnRequest;
/// use std::sync::Arc;
///
/// let request = CdnRequest {
///     name: Arc::from("example.kin"),
/// };
/// assert_eq!(&*request.name, "example.kin");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CdnRequest {
    /// The target `.kin` domain name being requested.
    pub name: std::sync::Arc<str>,
}

/// A network payload containing the result of a CDN cache lookup.
///
/// If the requested `.kin` name is found in the node's local cache (e.g., the DHT
/// cache), the raw serialized bytes of the `NameEnvelope` are returned. Returning
/// raw bytes instead of a parsed struct avoids unnecessary deserialization overhead
/// on the proxy node when forwarding the payload back to the client.
///
/// # Examples
/// ```rust
/// use kinetic_types::cdn::CdnResponse;
///
/// // A cache miss
/// let response_miss = CdnResponse { record: None };
///
/// // A cache hit (raw bytes of a NameEnvelope)
/// let response_hit = CdnResponse { record: Some(vec![0x01, 0x02, 0x03]) };
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CdnResponse {
    /// The serialized `NameEnvelope` bytes if found, or `None` if the name is not cached.
    pub record: Option<Vec<u8>>,
}
