use base64::{engine::general_purpose::URL_SAFE_NO_PAD as b64_url, Engine};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::did::KineticDid;
use crate::error::KidError;

/// A verification key listed as a controller of a [`KidDocument`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ControllerKey {
    /// A fragment URI identifying this key within the DID document (e.g. `did:kin:…#key-0`).
    pub id: String,
    #[serde(rename = "type")]
    /// The key algorithm; always `"Ed25519"` in v1.
    pub key_type: String,
    /// The Base64url-encoded raw public key bytes.
    pub public_key: String,
}

/// A pointer from a [`KidDocument`] to a published [`CapabilityManifest`](crate::manifest::CapabilityManifest).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManifestPointer {
    /// Optional SHA-256 hash of the manifest for integrity verification.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    /// Zero or more retrieval URLs for the manifest (e.g. HTTPS, IPFS).
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub locations: Vec<String>,
}

/// A Kinetic Identity Document (KID) — the W3C DID-compatible root of identity.
///
/// Identifies a Kinetic user and binds their Ed25519 public keys to a
/// `did:kin:<hash>` decentralized identifier. The document is signed with the
/// controller key and includes a Proof-of-Work nonce to prevent spam.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KidDocument {
    #[serde(rename = "type")]
    /// Schema type tag; always `"kinetic.kid.v1"` for v1 documents.
    pub doc_type: String,
    /// The `did:kin:<hash>` identifier for this document.
    pub kid: KineticDid,
    /// Unix timestamp (seconds) when this document was created.
    pub created_at: u64,
    /// Ordered list of Ed25519 verification keys that control this DID.
    pub controller_keys: Vec<ControllerKey>,
    /// Optional pointer to a [`CapabilityManifest`](crate::manifest::CapabilityManifest).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manifest: Option<ManifestPointer>,
    /// Base64url-encoded public keys authorised to revoke this document.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub revocation_keys: Vec<String>,
    /// Base64url-encoded Ed25519 signature over the JCS-canonical document (excluding this field).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

impl KidDocument {
    /// Returns the canonical JCS serialization of the document without the signature.
    pub fn canonicalize(&self) -> Result<String, KidError> {
        let mut unsigned_doc = self.clone();
        unsigned_doc.signature = None; // Omit signature for canonicalization

        serde_jcs::to_string(&unsigned_doc)
            .map_err(|e| KidError::CanonicalizationError(e.to_string()))
    }

    /// Verifies the signature of the document using the listed controller keys.
    /// This requires parsing the signature, canonicalizing the doc, and trying the controller keys.
    /// In v1, it must be signed by at least one valid Ed25519 controller key.
    pub fn verify(&self) -> Result<(), KidError> {
        let sig_b64 = self.signature.as_ref().ok_or(KidError::MissingSignature)?;
        let sig_bytes = b64_url.decode(sig_b64)?;

        if sig_bytes.len() != 64 {
            return Err(KidError::InvalidSignature);
        }
        let signature = Signature::from_bytes(sig_bytes.as_slice().try_into().unwrap());

        let msg_str = self.canonicalize()?;
        let msg_bytes = msg_str.as_bytes();

        let method_specific_id = self.kid.as_str().trim_start_matches("did:kin:");

        for key in &self.controller_keys {
            if key.key_type == "Ed25519" {
                if let Ok(pk_bytes) = b64_url.decode(&key.public_key) {
                    if let Ok(pk_array) = pk_bytes.as_slice().try_into() {
                        if let Ok(public_key) = VerifyingKey::from_bytes(pk_array) {
                            use sha2::{Digest, Sha256};
                            let mut hasher = Sha256::new();
                            hasher.update(pk_bytes.as_slice());
                            let hash = hasher.finalize();
                            let mut hex_hash = String::new();
                            for byte in hash {
                                use std::fmt::Write;
                                let _ = write!(&mut hex_hash, "{:02x}", byte);
                            }

                            // Ensure that the key signing the document actually matches the DID hash!
                            if hex_hash != method_specific_id {
                                continue;
                            }

                            if public_key.verify(msg_bytes, &signature).is_ok() {
                                return Ok(());
                            }
                        }
                    }
                }
            }
        }

        Err(KidError::InvalidSignature)
    }

    /// Helper to sign the document with a given keypair and return the signed document.
    pub fn sign(mut self, keypair: &ed25519_dalek::SigningKey) -> Result<Self, KidError> {
        use ed25519_dalek::Signer;
        let msg_str = self.canonicalize()?;
        let signature = keypair.sign(msg_str.as_bytes());
        self.signature = Some(b64_url.encode(signature.to_bytes()));
        Ok(self)
    }
}
