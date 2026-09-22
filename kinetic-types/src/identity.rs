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
///
/// This container is used to securely attach a self-sovereign W3C DID document 
/// (from Layer 2 `kinetic-kid`) to a specific `.kin` network name. It includes 
/// the owner's cryptographic signature over the combined payload to prove they 
/// authorized the attachment.
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
    /// # Security
    /// The 32-byte `network_salt` prefix guarantees Cross-Network Replay Protection. 
    /// A signature produced on the production `.kin` network cannot be maliciously 
    /// replayed on a private `.corp` or test network because the underlying byte 
    /// payload will fundamentally mismatch.
    ///
    /// # Examples
    /// ```rust
    /// use kinetic_types::identity::AuthorizedKid;
    /// 
    /// let kid_json = r#"{
    ///     "type": "kinetic.kid.v1",
    ///     "id": "did:kin:0000000000000000000000000000000000000000000000000000000000000000",
    ///     "created_at": 1700000000,
    ///     "controller_keys": [],
    ///     "revocation_keys": []
    /// }"#;
    /// let kid_doc = serde_json::from_str(kid_json).unwrap();
    /// 
    /// let auth = AuthorizedKid {
    ///     name: "example.kin".to_string(),
    ///     kid_doc,
    ///     owner_signature: vec![],
    /// };
    /// 
    /// let production_network_salt = [0x42; 32];
    /// let bytes = auth.signable_bytes(&production_network_salt);
    /// assert!(bytes.len() > 32);
    /// ```
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
///
/// This container is used to securely attach a time-bounded capability manifest 
/// (e.g., routing hints or service endpoints) to a specific `.kin` network name. 
/// It includes the owner's cryptographic signature to prove authorization.
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
    /// # Security
    /// Enforces Cross-Network Replay Protection by prepending the network-specific 
    /// 32-byte salt.
    ///
    /// # Examples
    /// ```rust
    /// use kinetic_types::identity::AuthorizedManifest;
    /// 
    /// let manifest_json = r#"{
    ///     "type": "kinetic.manifest.v1",
    ///     "kid": "did:kin:0000000000000000000000000000000000000000000000000000000000000000",
    ///     "version": 1,
    ///     "valid_from": 1700000000,
    ///     "expires_at": 1800000000,
    ///     "services": []
    /// }"#;
    /// let manifest = serde_json::from_str(manifest_json).unwrap();
    /// 
    /// let auth = AuthorizedManifest {
    ///     name: "example.kin".to_string(),
    ///     manifest,
    ///     kid_doc: None,
    ///     owner_signature: vec![],
    /// };
    /// 
    /// let test_network_salt = [0xFF; 32];
    /// let bytes = auth.signable_bytes(&test_network_salt);
    /// assert!(bytes.len() > 32);
    /// ```
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
