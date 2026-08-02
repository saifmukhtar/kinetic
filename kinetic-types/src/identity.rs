use serde::{Deserialize, Serialize};

/// Authorized Key Identifier (KID) document bound to a `.kin` domain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizedKid {
    /// Domain name associated with this KID.
    pub name: String,
    /// Embedded KID document containing public keys and controller data.
    pub kid_doc: kinetic_kid::document::KidDocument,
    /// Domain owner's signature verifying the KID attachment.
    pub owner_signature: Vec<u8>,
}

impl AuthorizedKid {
    /// Serializes this KID authorization into a canonical byte string for owner signature verification.
    ///
    /// The byte layout is:
    /// `{NETWORK_ID}-auth-kid-v1` + `u32_be(name.len())` + `name_bytes` + `u32_be(canon_json.len())` + `canon_json_bytes`
    ///
    /// The `{NETWORK_ID}` prefix prevents a signature produced on one Kinetic network (e.g. `.kin`)
    /// from being replayed on another (e.g. `.corp`).
    ///
    /// # Returns
    ///
    /// A `Vec<u8>` containing the fully serialized, network-scoped signable payload.
    pub fn signable_bytes(&self, network_id: &str) -> Vec<u8> {
        let prefix_suffix = b"-auth-kid-v1";
        let canon_bytes = self.kid_doc.canonicalize().unwrap_or_default();
        let canon_bytes = canon_bytes.as_bytes();
        let mut bytes = Vec::with_capacity(
            network_id.len() + prefix_suffix.len() + 4 + self.name.len() + 4 + canon_bytes.len(),
        );
        bytes.extend_from_slice(network_id.as_bytes());
        bytes.extend_from_slice(prefix_suffix);
        bytes.extend_from_slice(&(self.name.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.name.as_bytes());
        bytes.extend_from_slice(&(canon_bytes.len() as u32).to_be_bytes());
        bytes.extend_from_slice(canon_bytes);
        bytes
    }
}

/// Authorized capability manifest bound to a `.kin` domain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizedManifest {
    /// Domain name associated with this capability manifest.
    pub name: String,
    /// Embedded capability manifest structure.
    pub manifest: kinetic_kid::manifest::CapabilityManifest,
    /// Optional associated KID document.
    pub kid_doc: Option<kinetic_kid::document::KidDocument>,
    /// Domain owner's signature verifying the manifest attachment.
    pub owner_signature: Vec<u8>,
}

impl AuthorizedManifest {
    /// Serializes this manifest authorization into a canonical byte string for owner signature verification.
    ///
    /// The byte layout is:
    /// `{NETWORK_ID}-auth-manifest-v1` + `u32_be(name.len())` + `name_bytes` + `u32_be(canon_json.len())` + `canon_json_bytes`
    ///
    /// # Returns
    ///
    /// A `Vec<u8>` containing the fully serialized, network-scoped signable payload.
    pub fn signable_bytes(&self, network_id: &str) -> Vec<u8> {
        let prefix_suffix = b"-auth-manifest-v1";
        let canon_bytes = self.manifest.canonicalize().unwrap_or_default();
        let canon_bytes = canon_bytes.as_bytes();
        let mut bytes = Vec::with_capacity(
            network_id.len() + prefix_suffix.len() + 4 + self.name.len() + 4 + canon_bytes.len(),
        );
        bytes.extend_from_slice(network_id.as_bytes());
        bytes.extend_from_slice(prefix_suffix);
        bytes.extend_from_slice(&(self.name.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.name.as_bytes());
        bytes.extend_from_slice(&(canon_bytes.len() as u32).to_be_bytes());
        bytes.extend_from_slice(canon_bytes);
        bytes
    }
}
