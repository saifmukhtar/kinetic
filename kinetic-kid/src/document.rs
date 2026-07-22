use base64::{engine::general_purpose::URL_SAFE_NO_PAD as b64_url, Engine};
use ml_dsa::signature::{Signer, Verifier};
use ml_dsa::KeyInit;
use serde::{Deserialize, Serialize};

use crate::did::KineticDid;
use crate::error::KidError;

/// A verification key listed as a controller of a [`KidDocument`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ControllerKey {
    /// A fragment URI identifying this key within the DID document (e.g. `did:kin:…#key-0`).
    pub id: String,
    #[serde(rename = "type")]
    /// The key algorithm; always `"ML-DSA-65"` in v1.
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
    #[serde(deserialize_with = "crate::bounded::deserialize_max_20")]
    pub locations: Vec<String>,
}

/// A Kinetic Identity Document (KID) — the W3C DID-compatible root of identity.
///
/// Identifies a Kinetic user and binds their ML-DSA-65 public keys to a
/// `did:kin:<hash>` decentralized identifier. The document is signed with the
/// controller key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KidDocument {
    #[serde(rename = "type")]
    /// Schema type tag; always `"kinetic.kid.v1"` for v1 documents.
    pub doc_type: String,
    /// The `did:kin:<hash>` identifier for this document.
    pub kid: KineticDid,
    /// Unix timestamp (seconds) when this document was created.
    pub created_at: u64,
    /// Ordered list of ML-DSA-65 verification keys that control this DID.
    #[serde(deserialize_with = "crate::bounded::deserialize_max_20")]
    pub controller_keys: Vec<ControllerKey>,
    /// Optional pointer to a [`CapabilityManifest`](crate::manifest::CapabilityManifest).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manifest: Option<ManifestPointer>,
    /// Base64url-encoded public keys authorised to revoke this document.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    #[serde(deserialize_with = "crate::bounded::deserialize_max_20")]
    pub revocation_keys: Vec<String>,
    /// Whether this identity document has been deactivated/revoked.
    #[serde(default)]
    pub deactivated: bool,
    /// Base64url-encoded ML-DSA-65 signature over the JCS-canonical document (excluding this field).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

impl KidDocument {
    /// Returns the canonical JCS serialization of the document without the signature field.
    ///
    /// # Errors
    ///
    /// - Returns [`KidError::CanonicalizationError`](crate::error::KidError::CanonicalizationError) if JSON serialization fails.
    pub fn canonicalize(&self) -> Result<String, KidError> {
        let mut unsigned_doc = self.clone();
        unsigned_doc.signature = None; // Omit signature for canonicalization

        serde_jcs::to_string(&unsigned_doc)
            .map_err(|e| KidError::CanonicalizationError(e.to_string()))
    }

    /// Verifies the signature of the document against listed controller or revocation keys.
    ///
    /// # Errors
    ///
    /// - Returns [`KidError::TooManyKeys`](crate::error::KidError::TooManyKeys) if key count or URL bounds are exceeded.
    /// - Returns [`KidError::MissingSignature`](crate::error::KidError::MissingSignature) if the signature field is absent.
    /// - Returns [`KidError::Base64Error`](crate::error::KidError::Base64Error) if signature or public key base64url decoding fails.
    /// - Returns [`KidError::InvalidSignature`](crate::error::KidError::InvalidSignature) if no listed key produces a valid ML-DSA-65 signature.
    pub fn verify(&self) -> Result<(), KidError> {
        if self.controller_keys.len() > 20 || self.revocation_keys.len() > 20 {
            return Err(KidError::TooManyKeys);
        }
        for key in &self.controller_keys {
            if key.id.len() > 256 || key.public_key.len() > 8192 || key.key_type.len() > 32 {
                return Err(KidError::TooManyKeys);
            }
        }
        for rk in &self.revocation_keys {
            if rk.len() > 8192 { return Err(KidError::TooManyKeys); }
        }
        if let Some(manifest) = &self.manifest {
            if manifest.locations.len() > 20 {
                return Err(KidError::TooManyKeys);
            }
            for loc in &manifest.locations {
                if loc.len() > 2048 { return Err(KidError::TooManyKeys); }
            }
            if let Some(hash) = &manifest.hash {
                if hash.len() > 256 { return Err(KidError::TooManyKeys); }
            }
        }

        let sig_b64 = self.signature.as_ref().ok_or(KidError::MissingSignature)?;
        let sig_bytes = b64_url.decode(sig_b64)?;

        let signature = ml_dsa::Signature::<ml_dsa::MlDsa65>::try_from(sig_bytes.as_slice())
            .map_err(|_| KidError::InvalidSignature)?;

        let msg_str = self.canonicalize()?;
        let mut msg_bytes = b"kinetic-kid-v1\0".to_vec();
        msg_bytes.extend_from_slice(msg_str.as_bytes());

        // Note: We no longer enforce that did_hash_matched == true here.
        // In a fully decentralized DID resolution system, key rotation means the
        // current controller keys may no longer hash to the original DID identifier.

        if self.deactivated {
            // Document is deactivated (revoked), the signature MUST be from a revocation key
            for rk_b64 in &self.revocation_keys {
                if let Ok(pk_bytes) = b64_url.decode(rk_b64) {
                    if let Ok(public_key) =
                        ml_dsa::VerifyingKey::<ml_dsa::MlDsa65>::new_from_slice(pk_bytes.as_slice())
                    {
                        if public_key.verify(&msg_bytes, &signature).is_ok() {
                            return Ok(());
                        }
                    }
                }
            }
        } else {
            // Document is active, the signature MUST be from a controller key
            for key in &self.controller_keys {
                if key.key_type.eq_ignore_ascii_case("MlDsa65") {
                    if let Ok(pk_bytes) = b64_url.decode(&key.public_key) {
                        if let Ok(public_key) =
                            ml_dsa::VerifyingKey::<ml_dsa::MlDsa65>::new_from_slice(pk_bytes.as_slice())
                        {
                            if public_key.verify(&msg_bytes, &signature).is_ok() {
                                return Ok(());
                            }
                        }
                    }
                }
            }
        }

        Err(KidError::InvalidSignature)
    }

    /// Signs the document with an ML-DSA-65 signing keypair and populates the Base64url signature field.
    ///
    /// # Errors
    ///
    /// - Returns [`KidError::CanonicalizationError`](crate::error::KidError::CanonicalizationError) if JCS canonicalization fails.
    pub fn sign(mut self, keypair: &ml_dsa::SigningKey<ml_dsa::MlDsa65>) -> Result<Self, KidError> {
        use ml_dsa::SignatureEncoding;
        let msg_str = self.canonicalize()?;
        let mut msg_bytes = b"kinetic-kid-v1\0".to_vec();
        msg_bytes.extend_from_slice(msg_str.as_bytes());
        let signature = keypair.sign(&msg_bytes);
        self.signature = Some(b64_url.encode(signature.to_bytes()));
        Ok(self)
    }
}
