use serde::{Deserialize, Serialize};
use std::fmt;
use crate::error::KidError;

/// A strict parser for the `did:kin:<method-specific-id>` identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KineticDid {
    id: String,
}

impl KineticDid {
    /// Creates a new KineticDid, validating the prefix.
    pub fn new(id_str: &str) -> Result<Self, KidError> {
        if !id_str.starts_with("did:kin:") {
            return Err(KidError::InvalidDidPrefix);
        }
        
        let method_specific_id = &id_str["did:kin:".len()..];
        if method_specific_id.is_empty() {
            return Err(KidError::InvalidDidFormat);
        }
        
        Ok(KineticDid {
            id: id_str.to_string(),
        })
    }

    /// Returns the full DID string
    pub fn as_str(&self) -> &str {
        &self.id
    }
}

impl fmt::Display for KineticDid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.id)
    }
}

// Custom Serialize to output as string
impl Serialize for KineticDid {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.id)
    }
}

// Custom Deserialize to parse from string and strictly validate
impl<'de> Deserialize<'de> for KineticDid {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        KineticDid::new(&s).map_err(serde::de::Error::custom)
    }
}
