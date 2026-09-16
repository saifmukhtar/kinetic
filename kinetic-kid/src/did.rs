//! Decentralized Identifier (DID) parsing and validation for the Kinetic Network.
//!
//! This module enforces the strict W3C DID Core Specification and ensures that all 
//! identity pointers strictly conform to the 64-character lowercase hex requirement.

use crate::error::Error;
use serde::{Deserialize, Serialize};
use std::fmt;

/// A Decentralized Identifier (DID) representing a self-sovereign identity on the Kinetic network.
///
/// The identifier format defaults to `did:kin:<method-specific-id>`, though the exact 
/// namespace prefix is dynamically configured at compile time via the `KINETIC_DID_PREFIX` 
/// environment variable. The `<method-specific-id>` must be exactly 64 lowercase 
/// hexadecimal characters, representing the SHA-256 hash of the identity's primary public key.
/// 
/// This cryptographically binds the DID string to its genesis controller key,
/// establishing a verifiable root of trust without requiring a central registry.
///
/// # Security
/// A `Did` contains only public routing information and a public key hash. 
/// It contains no sensitive material and is safe to log, broadcast, and embed 
/// directly inside JSON manifests.
///
/// # Examples
/// ```rust
/// use kinetic_kid::Did;
///
/// // A valid Kinetic DID using a 64-character lowercase hex string
/// let did_string = format!("did:kin:{}", "a".repeat(64));
/// let did = Did::new(&did_string).unwrap();
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Did {
    id: String,
}

impl Did {
    /// Creates a new `Did`, validating the scheme prefix and hex-encoded SHA-256 method-specific ID.
    ///
    /// # Errors
    ///
    /// - Returns [`Error::InvalidDidPrefix`] if the string does not start with the environment-defined prefix (typically `did:kin:`).
    /// - Returns [`Error::InvalidDidHexLength`] if the method-specific ID is not exactly 64 characters long.
    /// - Returns [`Error::InvalidDidHexCharacters`] if the method-specific ID contains uppercase hex or non-hex characters.
    ///
    /// # Examples
    /// ```rust
    /// use kinetic_kid::Did;
    /// 
    /// let valid_id = format!("did:kin:{}", "0".repeat(64));
    /// assert!(Did::new(&valid_id).is_ok());
    /// 
    /// // Fails due to uppercase hex characters
    /// let invalid_id = format!("did:kin:{}", "A".repeat(64));
    /// assert!(Did::new(&invalid_id).is_err());
    /// ```
    pub fn new(id_str: &str) -> Result<Self, Error> {
        let expected_prefix = env!("KINETIC_DID_PREFIX");
        if !id_str.starts_with(expected_prefix) {
            return Err(Error::InvalidDidPrefix);
        }

        let method_specific_id = &id_str[expected_prefix.len()..];
        if method_specific_id.len() != 64 {
            return Err(Error::InvalidDidHexLength);
        }

        if !method_specific_id
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        {
            return Err(Error::InvalidDidHexCharacters);
        }

        Ok(Did {
            id: id_str.to_string(),
        })
    }

    /// Returns the full, canonical DID string (e.g., `did:kin:000...`).
    pub fn as_str(&self) -> &str {
        &self.id
    }
}

/// Formats the DID as its canonical string representation.
impl fmt::Display for Did {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.id)
    }
}

/// Serializes the DID transparently as a canonical string.
impl Serialize for Did {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.id)
    }
}

/// Deserializes a string into a DID, enforcing strict format validation.
impl<'de> Deserialize<'de> for Did {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Did::new(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn test_did_parsing_no_crash(s in "\\PC*") {
            let _ = Did::new(&s);
        }
    }
}
