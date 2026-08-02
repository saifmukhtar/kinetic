//! High-performance IPC proxy payloads for browser extension and desktop integration.
//!
//! Provides zero-copy, reference-counted HTTP request and response structures ([`ProxyRequest`],
//! [`ProxyResponse`]) used to bridge client interfaces (e.g. browser extensions, PAC proxy daemons,
//! and native desktop apps) with the underlying Kinetic node and gateway.
//!
//! Header keys, values, methods, and paths leverage [`Arc<str>`](std::sync::Arc) to eliminate redundant
//! heap allocations across concurrent proxy worker threads.

use serde::{Deserialize, Serialize};

/// High-performance HTTP proxy request container for client IPC forwarding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyRequest {
    /// HTTP method (e.g. `GET`, `POST`, `OPTIONS`).
    pub method: std::sync::Arc<str>,
    /// Request target URL path and query parameters (e.g. `/index.html?v=1`).
    pub path: std::sync::Arc<str>,
    /// Key-value collection of HTTP request headers.
    pub headers: Vec<(std::sync::Arc<str>, std::sync::Arc<str>)>,
    /// Raw HTTP request payload body.
    #[serde(with = "serde_bytes_wrapper")]
    pub body: bytes::Bytes,
}

/// High-performance HTTP proxy response container returned to client adapters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyResponse {
    /// Standard HTTP status code (e.g. `200`, `404`, `502`).
    pub status: u16,
    /// Key-value collection of HTTP response headers.
    pub headers: Vec<(std::sync::Arc<str>, std::sync::Arc<str>)>,
    /// Raw HTTP response payload body.
    #[serde(with = "serde_bytes_wrapper")]
    pub body: bytes::Bytes,
}

impl ProxyResponse {
    /// Returns true if the HTTP status code is in the successful range (`200..=299`).
    pub fn is_success(&self) -> bool {
        self.status >= 200 && self.status < 300
    }
}

/// Helper module for efficient binary serialization of [`bytes::Bytes`] payloads.
pub mod serde_bytes_wrapper {
    use bytes::Bytes;
    use serde::{Deserializer, Serializer};

    /// Serializes [`Bytes`] using standard binary byte slice encoding.
    pub fn serialize<S>(bytes: &Bytes, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serde_bytes::serialize(bytes.as_ref(), serializer)
    }

    /// Deserializes binary byte slice directly into [`Bytes`].
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Bytes, D::Error>
    where
        D: Deserializer<'de>,
    {
        let b: Vec<u8> = serde_bytes::deserialize(deserializer)?;
        Ok(Bytes::from(b))
    }
}
