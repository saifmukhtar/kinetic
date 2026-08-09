use base64::{engine::general_purpose::URL_SAFE_NO_PAD as b64_url, Engine};

use serde::{Deserialize, Serialize};

use crate::did::KineticDid;
use crate::document::KidDocument;
use crate::error::KidError;

/// A single service endpoint published in a [`CapabilityManifest`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServiceEntry {
    /// A local fragment ID for this service (e.g. `"#website"`).
    pub id: String,
    #[serde(rename = "type")]
    /// The service category (e.g. `"website"`, `"api"`).
    pub service_type: String,
    /// The transport protocol (e.g. `"https"`, `"grpc"`).
    pub protocol: String,
    /// The fully-qualified endpoint URI.
    pub endpoint: String,
}

/// A versioned list of service endpoints associated with a KID document.
///
/// A `CapabilityManifest` is signed separately from the [`KidDocument`] and
/// can be updated independently, allowing service endpoints to change without
/// creating a new DID. It must be signed by one of the controller keys listed
/// in the corresponding KID document.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapabilityManifest {
    #[serde(rename = "type")]
    /// Schema type tag; always `"kinetic.manifest.v1"` for v1 manifests.
    pub doc_type: String,
    /// The `did:kin:<hash>` identifier that this manifest belongs to.
    pub kid: KineticDid,
    /// Monotonically increasing version number; resolvers prefer higher versions.
    pub version: u64,
    /// Unix timestamp (seconds) defining when this manifest becomes active.
    ///
    /// Verified against the network's consensus clock (e.g., Drand beacon timestamps)
    /// to prevent malicious forward-dating. The network permits a maximum 300-second 
    /// (5-minute) clock skew allowance.
    pub valid_from: u64,
    /// Optional Unix timestamp (seconds) dictating when this manifest expires.
    ///
    /// If provided, network nodes will reject or drop this manifest once the consensus
    /// clock passes this time, forcing the controller to publish a fresh manifest.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    /// Ordered list of service endpoints this DID owner is advertising.
    #[serde(deserialize_with = "crate::bounded::deserialize_max_50")]
    pub services: Vec<ServiceEntry>,
    /// Base64url-encoded ML-DSA-65 signature over the JCS-canonical manifest (excluding this field).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

impl CapabilityManifest {
    /// Returns the canonical JCS serialization of the manifest without the signature field.
    ///
    /// # Errors
    ///
    /// - Returns [`KidError::CanonicalizationError`] if JSON serialization fails.
    pub fn canonicalize(&self) -> Result<String, KidError> {
        let mut unsigned_manifest = self.clone();
        unsigned_manifest.signature = None; // Omit signature for canonicalization

        serde_jcs::to_string(&unsigned_manifest)
            .map_err(|e| KidError::CanonicalizationError(e.to_string()))
    }

    /// Verifies the signature of the manifest using the authorized controller keys in the provided KID Document
    /// against the local client's wall-clock time.
    ///
    /// # Security Warning: Client-Side Use Only
    ///
    /// This function uses the local unverified system clock (`web_time::SystemTime::now()`) and is strictly
    /// for offline, client-side, or CLI use. It is vulnerable to clock drift and local time manipulation.
    /// **Consensus nodes and daemons MUST NOT use this function.** They must use [`CapabilityManifest::verify_at_time`] and inject
    /// the secure deterministic network consensus timestamp (e.g., Drand beacon time).
    ///
    /// # Errors
    ///
    /// - Returns [`KidError::TooManyKeys`] if key count, service count, or URI bounds are exceeded.
    /// - Returns [`KidError::UnauthorizedManifestSignature`] if manifest DID does not match document DID or signature is not authorized.
    /// - Returns [`KidError::InvalidValidFrom`] if `valid_from` is in the future beyond 5 minutes skew.
    /// - Returns [`KidError::ManifestExpired`] if `expires_at` timestamp has passed.
    /// - Returns [`KidError::MissingSignature`] if the signature field is absent.
    /// - Returns [`KidError::Base64Error`] if signature decoding fails.
    /// - Returns [`KidError::InvalidSignature`] if signature bytes are invalid.
    pub fn verify_local(&self, kid_document: &KidDocument) -> Result<(), KidError> {
        let current_time = web_time::SystemTime::now()
            .duration_since(web_time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.verify_at_time(kid_document, current_time)
    }

    /// Verifies the signature of the manifest using the authorized controller keys in the provided KID Document
    /// against an explicit network Unix timestamp (e.g. Drand consensus kyn timestamp).
    ///
    /// # Errors
    ///
    /// - Returns [`KidError::TooManyKeys`] if key count, service count, or URI bounds are exceeded.
    /// - Returns [`KidError::UnauthorizedManifestSignature`] if manifest DID does not match document DID or signature is not authorized.
    /// - Returns [`KidError::InvalidValidFrom`] if `valid_from` is in the future beyond 5 minutes skew relative to `current_time_secs`.
    /// - Returns [`KidError::ManifestExpired`] if `expires_at` timestamp has passed relative to `current_time_secs`.
    /// - Returns [`KidError::MissingSignature`] if the signature field is absent.
    /// - Returns [`KidError::Base64Error`] if signature decoding fails.
    /// - Returns [`KidError::InvalidSignature`] if signature bytes are invalid.
    pub fn verify_at_time(&self, kid_document: &KidDocument, current_time_secs: u64) -> Result<(), KidError> {
        if kid_document.controller_keys.len() > 20 {
            return Err(KidError::TooManyKeys);
        }

        if self.kid != kid_document.kid {
            return Err(KidError::UnauthorizedManifestSignature);
        }

        if self.valid_from > current_time_secs + 300 {
            return Err(KidError::InvalidValidFrom);
        }
        if let Some(expires) = self.expires_at {
            if current_time_secs >= expires {
                return Err(KidError::ManifestExpired);
            }
        }
        if self.services.len() > 50 {
            return Err(KidError::TooManyKeys);
        }
        for svc in &self.services {
            if svc.id.len() > 256
                || svc.service_type.len() > 256
                || svc.protocol.len() > 64
                || svc.endpoint.len() > crate::LIMITS_KID_MAX_ENDPOINT_BYTES
            {
                return Err(KidError::TooManyKeys);
            }
        }

        let sig_b64 = self.signature.as_ref().ok_or(KidError::MissingSignature)?;
        let sig_bytes = b64_url.decode(sig_b64)?;

        let signature = ml_dsa::Signature::<ml_dsa::MlDsa65>::try_from(sig_bytes.as_slice())
            .map_err(|_| KidError::InvalidSignature)?;

        let msg_str = self.canonicalize()?;
        let mut msg_bytes = b"kinetic-manifest-v1\0".to_vec();
        msg_bytes.extend_from_slice(msg_str.as_bytes());

        for key in &kid_document.controller_keys {
            if key.key_type.eq_ignore_ascii_case("MlDsa65") || key.key_type.eq_ignore_ascii_case("ML-DSA-65") {
                if let Ok(pk_bytes) = b64_url.decode(&key.public_key) {
                    use ml_dsa::KeyInit;
                    if let Ok(public_key) =
                        ml_dsa::VerifyingKey::<ml_dsa::MlDsa65>::new_from_slice(&pk_bytes)
                    {
                        use ml_dsa::signature::Verifier;
                        if public_key.verify(&msg_bytes, &signature).is_ok() {
                            return Ok(());
                        }
                    }
                }
            }
        }

        Err(KidError::UnauthorizedManifestSignature)
    }

    /// Helper to sign the manifest with an ML-DSA-65 keypair and return the signed manifest.
    ///
    /// # Errors
    ///
    /// - Returns [`KidError::CanonicalizationError`] if JCS canonicalization fails.
    pub fn sign(mut self, keypair: &ml_dsa::SigningKey<ml_dsa::MlDsa65>) -> Result<Self, KidError> {
        use ml_dsa::signature::Signer;
        use ml_dsa::SignatureEncoding;
        let msg_str = self.canonicalize()?;
        let mut msg_bytes = b"kinetic-manifest-v1\0".to_vec();
        msg_bytes.extend_from_slice(msg_str.as_bytes());
        let signature = keypair.sign(&msg_bytes);
        self.signature = Some(b64_url.encode(signature.to_bytes()));
        Ok(self)
    }
}
