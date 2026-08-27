//! Authorized Kinetic Identity Document (KID) documents and capability manifests.
//!
//! Provides the authorization containers binding decentralized identities (KIDs) and capability
//! manifests to `.kin` names.
//!
//! ## Cross-Network Replay Protection
//!
//! Every authorization payload prefixes serialized bytes with the unique 32-byte `network_salt`:
//! - [`AuthorizedKid::signable_bytes`] produces:
//!   `network_salt` + `b"-auth-kid-v1"` + `u32_be(name.len())` + `name_bytes` + `u32_be(canon_json.len())` + `canon_json_bytes`
//! - [`AuthorizedManifest::signable_bytes`] produces:
//!   `network_salt` + `b"-auth-manifest-v1"` + `u32_be(name.len())` + `name_bytes` + `u32_be(canon_json.len())` + `canon_json_bytes`
//!
//! This deterministic framing guarantees that signatures generated for the production `.kin` network
//! cannot be replayed on alternative or test networks (e.g. `.corp` or `.local`).

use serde::{Deserialize, Serialize};

/// Authorized Kinetic Identity Document (KID) document bound to a `.kin` name.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizedKid {
    /// Name associated with this KID.
    pub name: String,
    /// Embedded KID document containing public keys and controller data.
    pub kid_doc: kinetic_kid::document::Document,
    /// Name owner's signature verifying the KID attachment.
    pub owner_signature: Vec<u8>,
}

impl AuthorizedKid {
    /// Serializes this KID authorization into a canonical byte string for owner signature verification.
    ///
    /// The byte layout is:
    /// `network_salt` (32 bytes) + `b"-auth-kid-v1"` + `u32_be(name.len())` + `name_bytes` + `u32_be(canon_json.len())` + `canon_json_bytes`
    ///
    /// The 32-byte `network_salt` prefix prevents a signature produced on one Kinetic network (e.g. `.kin`)
    /// from being replayed on another (e.g. `.corp`).
    ///
    /// # Returns
    ///
    /// A `Vec<u8>` containing the fully serialized, network-scoped signable payload.
    pub fn signable_bytes(&self, network_salt: &[u8; 32]) -> Vec<u8> {
        let name_separator = b"-auth-kid-v1";
        let canon_bytes = self.kid_doc.canonicalize().unwrap_or_default();
        let canon_bytes = canon_bytes.as_bytes();
        let mut bytes = Vec::with_capacity(
            network_salt.len() + name_separator.len() + 4 + self.name.len() + 4 + canon_bytes.len(),
        );
        bytes.extend_from_slice(network_salt);
        bytes.extend_from_slice(name_separator);
        bytes.extend_from_slice(&(self.name.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.name.as_bytes());
        bytes.extend_from_slice(&(canon_bytes.len() as u32).to_be_bytes());
        bytes.extend_from_slice(canon_bytes);
        bytes
    }
}

/// Authorized capability manifest bound to a `.kin` name.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuthorizedManifest {
    /// Name associated with this capability manifest.
    pub name: String,
    /// Embedded capability manifest structure.
    pub manifest: kinetic_kid::manifest::Manifest,
    /// Optional associated KID document.
    pub kid_doc: Option<kinetic_kid::document::Document>,
    /// Name owner's signature verifying the manifest attachment.
    pub owner_signature: Vec<u8>,
}

impl AuthorizedManifest {
    /// Serializes this manifest authorization into a canonical byte string for owner signature verification.
    ///
    /// The byte layout is:
    /// `network_salt` (32 bytes) + `b"-auth-manifest-v1"` + `u32_be(name.len())` + `name_bytes` + `u32_be(canon_json.len())` + `canon_json_bytes`
    ///
    /// # Returns
    ///
    /// A `Vec<u8>` containing the fully serialized, network-scoped signable payload.
    pub fn signable_bytes(&self, network_salt: &[u8; 32]) -> Vec<u8> {
        let name_separator = b"-auth-manifest-v1";
        let canon_bytes = self.manifest.canonicalize().unwrap_or_default();
        let canon_bytes = canon_bytes.as_bytes();
        let mut bytes = Vec::with_capacity(
            network_salt.len() + name_separator.len() + 4 + self.name.len() + 4 + canon_bytes.len(),
        );
        bytes.extend_from_slice(network_salt);
        bytes.extend_from_slice(name_separator);
        bytes.extend_from_slice(&(self.name.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.name.as_bytes());
        bytes.extend_from_slice(&(canon_bytes.len() as u32).to_be_bytes());
        bytes.extend_from_slice(canon_bytes);
        bytes
    }
}
