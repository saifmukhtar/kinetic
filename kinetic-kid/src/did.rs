use crate::error::KidError;
use serde::{Deserialize, Serialize};
use std::fmt;

/// A strict parser for the `did:kin:<method-specific-id>` identifier.
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
    /// - Returns [`KidError::InvalidDidFormat`] if the method-specific ID is empty.
    /// - Returns [`KidError::InvalidDidHexLength`] if the method-specific ID is not 64 characters long.
    /// - Returns [`KidError::InvalidDidHexCharacters`] if the method-specific ID contains uppercase hex or non-hex characters.
    pub fn new(id_str: &str) -> Result<Self, KidError> {
        if !id_str.starts_with("did:kin:") {
            return Err(KidError::InvalidDidPrefix);
        }

        let method_specific_id = &id_str["did:kin:".len()..];
        if method_specific_id.is_empty() {
            return Err(KidError::InvalidDidFormat);
        }

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
