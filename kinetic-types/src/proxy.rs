use serde::{Deserialize, Serialize};

/// Proxy Request
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyRequest {
    /// Method
    pub method: std::sync::Arc<str>,
    /// Path
    pub path: std::sync::Arc<str>,
    /// Headers
    pub headers: Vec<(std::sync::Arc<str>, std::sync::Arc<str>)>,
    /// Body
    #[serde(with = "serde_bytes_wrapper")]
    pub body: bytes::Bytes,
}

/// Proxy Response
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyResponse {
    /// Status
    pub status: u16,
    /// Headers
    pub headers: Vec<(std::sync::Arc<str>, std::sync::Arc<str>)>,
    /// Body
    #[serde(with = "serde_bytes_wrapper")]
    pub body: bytes::Bytes,
}

impl ProxyResponse {
    /// Returns true if the status code is between 200 and 299.
    pub fn is_success(&self) -> bool {
        self.status >= 200 && self.status < 300
    }
}

pub mod serde_bytes_wrapper {
    use bytes::Bytes;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Bytes, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serde_bytes::serialize(bytes.as_ref(), serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Bytes, D::Error>
    where
        D: Deserializer<'de>,
    {
        let b: Vec<u8> = serde_bytes::deserialize(deserializer)?;
        Ok(Bytes::from(b))
    }
}
