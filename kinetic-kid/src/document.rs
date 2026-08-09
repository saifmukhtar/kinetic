use base64::{engine::general_purpose::URL_SAFE_NO_PAD as b64_url, Engine};
use ml_dsa::signature::{Signer, Verifier};
use ml_dsa::KeyInit;
use serde::{Deserialize, Serialize};

use crate::did::KineticDid;
use crate::error::KidError;

/// An active verification key authorized to act on behalf of the identity.
///
/// Controller keys are considered "hot" keys. They are used in daily operations
/// to sign `CapabilityManifest`s, authorize the rotation of existing keys, and
/// prove ownership of the DID. They are explicitly NOT used for emergency deactivation.
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
    /// Cold-storage fallback keys authorized exclusively to revoke this identity.
    ///
    /// These Base64url-encoded ML-DSA-65 public keys cannot sign manifests or authorize
    /// standard updates. Their sole purpose is to sign a `deactivated: true` document
    /// in the event that the primary controller keys are compromised or lost, permanently
    /// burning the identity. Limited to 20 keys.
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
    /// - Returns [`KidError::CanonicalizationError`] if JSON serialization fails.
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
    /// - Returns [`KidError::TooManyKeys`] if key count or URL bounds are exceeded.
    /// - Returns [`KidError::MissingSignature`] if the signature field is absent.
    /// - Returns [`KidError::Base64Error`] if signature base64url decoding fails.
    /// - Returns [`KidError::InvalidSignature`] if no listed key produces a valid ML-DSA-65 signature.
    pub fn verify(&self) -> Result<(), KidError> {
        if self.controller_keys.len() > 20 || self.revocation_keys.len() > 20 {
            return Err(KidError::TooManyKeys);
        }
        for key in &self.controller_keys {
            if key.id.len() > 256 || key.public_key.len() > crate::LIMITS_KID_MAX_PUBLIC_KEY_BYTES || key.key_type.len() > 32 {
                return Err(KidError::TooManyKeys);
            }
        }
        for rk in &self.revocation_keys {
            if rk.len() > crate::LIMITS_KID_MAX_PUBLIC_KEY_BYTES {
                return Err(KidError::TooManyKeys);
            }
        }
        if let Some(manifest) = &self.manifest {
            if manifest.locations.len() > 20 {
                return Err(KidError::TooManyKeys);
            }
            for loc in &manifest.locations {
                if loc.len() > crate::LIMITS_KID_MAX_LOCATION_BYTES {
                    return Err(KidError::TooManyKeys);
                }
            }
            if let Some(hash) = &manifest.hash {
                if hash.len() > 256 {
                    return Err(KidError::TooManyKeys);
                }
            }
        }

        let sig_b64 = self.signature.as_ref().ok_or(KidError::MissingSignature)?;
        let sig_bytes = b64_url.decode(sig_b64)?;

        let signature = ml_dsa::Signature::<ml_dsa::MlDsa65>::try_from(sig_bytes.as_slice())
            .map_err(|_| KidError::InvalidSignature)?;

        let msg_str = self.canonicalize()?;
        let mut msg_bytes = b"kinetic-kid-v1\0".to_vec();
        msg_bytes.extend_from_slice(msg_str.as_bytes());

        // `verify()` is stateless: it only checks that the document is internally
        // self-consistent and that the signature was produced by one of the listed
        // controller keys. It intentionally does NOT check whether the `kid` DID
        // matches the hash of those keys, because after a key rotation the current
        // controller keys will differ from the genesis key that seeded the DID.
        //
        // For first-time publication, call `verify_genesis()` to enforce the
        // cryptographic DID↔key binding. For updates, the store layer checks that
        // the new document is signed by a key from the previously stored document.

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
                if key.key_type.eq_ignore_ascii_case("MlDsa65") || key.key_type.eq_ignore_ascii_case("ML-DSA-65") {
                    if let Ok(pk_bytes) = b64_url.decode(&key.public_key) {
                        if let Ok(public_key) =
                            ml_dsa::VerifyingKey::<ml_dsa::MlDsa65>::new_from_slice(
                                pk_bytes.as_slice(),
                            )
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

    /// Verifies the cryptographic genesis binding: that the `kid` DID identifier
    /// is the SHA-256 hash of the primary (first) controller key's raw public bytes.
    ///
    /// This check MUST be called during **first publication** of a KID document,
    /// before any document for this DID is stored. It ensures a DID cannot be
    /// claimed by an arbitrary key that has no cryptographic relationship to it.
    ///
    /// It must NOT be called on subsequent updates, because key rotation legitimately
    /// changes the controller keys while the DID stays the same.
    ///
    /// # Errors
    ///
    /// - Returns [`KidError::InvalidSignature`] if the document has no controller keys.
    /// - Returns [`KidError::Base64Error`] if the primary key is not valid Base64url.
    /// - Returns [`KidError::DidKeyMismatch`] if the DID hex suffix does not match
    ///   `hex(SHA-256(primary_controller_key_bytes))`.
    pub fn verify_genesis(&self) -> Result<(), KidError> {
        use sha2::{Digest, Sha256};
        use std::fmt::Write as FmtWrite;

        let primary_key = self
            .controller_keys
            .first()
            .ok_or(KidError::InvalidSignature)?;

        let pk_bytes = b64_url.decode(&primary_key.public_key)?;
        let hash = Sha256::digest(&pk_bytes);

        let mut expected_hex = String::with_capacity(64);
        for byte in hash {
            let _ = write!(expected_hex, "{:02x}", byte);
        }
        let expected_kid = format!("{}{}", env!("KINETIC_DID_PREFIX"), expected_hex);

        if self.kid.as_str() != expected_kid {
            return Err(KidError::DidKeyMismatch);
        }

        Ok(())
    }

    /// Checks whether `self` (the incoming updated document) was signed by a key
    /// that appeared in `previous_doc` (the currently stored document).
    ///
    /// Call this during **KID updates** (when a document already exists for the DID)
    /// to enforce the authorised key-rotation chain and prevent hijacking.
    ///
    /// # Returns
    ///
    /// `true` if the update is authorised by a prior controller key, `false` otherwise.
    pub fn is_authorized_update(&self, previous_doc: &KidDocument) -> bool {
        use ml_dsa::KeyInit;

        let sig_b64 = match self.signature.as_ref() {
            Some(s) => s,
            None => return false,
        };

        let sig_bytes = match b64_url.decode(sig_b64) {
            Ok(b) => b,
            Err(_) => return false,
        };

        let ml_sig = match ml_dsa::Signature::<ml_dsa::MlDsa65>::try_from(sig_bytes.as_slice()) {
            Ok(s) => s,
            Err(_) => return false,
        };

        let msg_str = match self.canonicalize() {
            Ok(s) => s,
            Err(_) => return false,
        };
        let mut msg_bytes = b"kinetic-kid-v1\0".to_vec();
        msg_bytes.extend_from_slice(msg_str.as_bytes());

        previous_doc.controller_keys.iter().any(|ck| {
            if !ck.key_type.eq_ignore_ascii_case("MlDsa65") && !ck.key_type.eq_ignore_ascii_case("ML-DSA-65") {
                return false;
            }
            if let Ok(pk_bytes) = b64_url.decode(&ck.public_key) {
                if let Ok(vk) =
                    ml_dsa::VerifyingKey::<ml_dsa::MlDsa65>::new_from_slice(pk_bytes.as_slice())
                {
                    use ml_dsa::signature::Verifier;
                    return vk.verify(&msg_bytes, &ml_sig).is_ok();
                }
            }
            false
        })
    }

    /// Signs the document with an ML-DSA-65 signing keypair and populates the Base64url signature field.
    ///
    /// # Errors
    ///
    /// - Returns [`KidError::CanonicalizationError`] if JCS canonicalization fails.
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
