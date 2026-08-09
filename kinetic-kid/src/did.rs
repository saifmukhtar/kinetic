use crate::error::KidError;
use serde::{Deserialize, Serialize};
use std::fmt;

/// A Decentralized Identifier (DID) representing a self-sovereign identity on the Kinetic network.
///
/// The identifier format is strictly `did:kin:<method-specific-id>`.
/// The method-specific ID must be exactly 64 lowercase hexadecimal characters,
/// representing the SHA-256 hash of the identity's primary ML-DSA-65 public key.
/// This cryptographically binds the DID string to its genesis controller key,
/// establishing a verifiable root of trust without requiring a central registry.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KineticDid {
    id: String,
}

impl KineticDid {
    /// Creates a new `KineticDid`, validating the scheme prefix and hex-encoded SHA-256 method-specific ID.
    ///
    /// # Errors
    ///
    /// - Returns [`KidError::InvalidDidPrefix`] if the string does not start with `did:kin:`.
    /// - Returns [`KidError::InvalidDidHexLength`] if the method-specific ID is not exactly 64 characters long.
    /// - Returns [`KidError::InvalidDidHexCharacters`] if the method-specific ID contains uppercase hex or non-hex characters.
    pub fn new(id_str: &str) -> Result<Self, KidError> {
        let expected_prefix = env!("KINETIC_DID_PREFIX");
        if !id_str.starts_with(expected_prefix) {
            return Err(KidError::InvalidDidPrefix);
        }

        let method_specific_id = &id_str[expected_prefix.len()..];
        if method_specific_id.len() != 64 {
            return Err(KidError::InvalidDidHexLength);
        }

        if !method_specific_id
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        {
            return Err(KidError::InvalidDidHexCharacters);
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

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn doesnt_crash_did_parsing(s in "\\PC*") {
            let _ = KineticDid::new(&s);
        }
    }
}
