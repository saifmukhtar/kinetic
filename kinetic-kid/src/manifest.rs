use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as b64_url};

use serde::{Deserialize, Serialize};

use crate::did::Did;
use crate::document::Document;
use crate::error::Error;

/// A single service endpoint published in a [`Manifest`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Service {
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
/// A `Manifest` is signed separately from the [`Document`] and
/// can be updated independently, allowing service endpoints to change without
/// creating a new DID. It must be signed by one of the controller keys listed
/// in the corresponding KID document.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Manifest {
    #[serde(rename = "type")]
    /// Schema type tag; always `"kinetic.manifest.v1"` for v1 manifests.
    pub doc_type: String,
    /// The `did:kin:<hash>` identifier that this manifest belongs to.
    pub kid: Did,
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
    pub services: Vec<Service>,
    /// Base64url-encoded ML-DSA-65 signature over the JCS-canonical manifest (excluding this field).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

impl Manifest {
    /// Returns the canonical JCS serialization of the manifest without the signature field.
    ///
    /// # Errors
    ///
    /// - Returns [`Error::CanonicalizationError`] if JSON serialization fails.
    pub fn canonicalize(&self) -> Result<String, Error> {
        let mut unsigned_manifest = self.clone();
        unsigned_manifest.signature = None; // Omit signature for canonicalization

        serde_jcs::to_string(&unsigned_manifest)
            .map_err(|e| Error::CanonicalizationError(e.to_string()))
    }

    /// Verifies the signature of the manifest using the authorized controller keys in the provided KID Document
    /// against an explicit Unix timestamp.
    ///
    /// # Time Verification Architecture
    ///
    /// Because `kinetic-kid` is a pure mathematical sandbox, it does not access the local operating system
    /// or browser clock. Time must be explicitly injected via the `unix_time` parameter.
    ///
    /// There are two ways to provide this time in client/WASM environments:
    ///
    /// 1. **The Secure Way (Recommended):** Fetch the latest VDF (Verifiable Delay Function) proof
    ///    from the Kinetic network, mathematically verify the proof locally, and convert the proven
    ///    network `Kyn` into a Unix timestamp. This ensures the document is validated against
    ///    the true consensus clock, preventing local clock manipulation.
    ///
    /// 2. **The Simple Way (Insecure/Offline):** Have the outer environment (e.g., JavaScript) fetch the
    ///    local wall clock time (e.g., `Math.floor(Date.now() / 1000)`) and inject it. This is vulnerable
    ///    to the user changing their device's calendar to bypass expiration dates.
    ///
    /// # Errors
    ///
    /// - Returns [`Error::KeyLimitExceeded`] if key count bounds are exceeded.
    /// - Returns [`Error::ServiceLimitExceeded`] if service bounds are exceeded.
    /// - Returns [`Error::StringLengthExceeded`] if string length bounds are exceeded.
    /// - Returns [`Error::UnauthorizedManifestSignature`] if manifest DID does not match document DID or signature is not authorized.
    /// - Returns [`Error::InvalidValidFrom`] if `valid_from` is in the future beyond 5 minutes skew relative to `current_time_secs`.
    /// - Returns [`Error::ManifestExpired`] if `expires_at` timestamp has passed relative to `current_time_secs`.
    /// - Returns [`Error::MissingSignature`] if the signature field is absent.
    /// - Returns [`Error::Base64Error`] if signature decoding fails.
    /// - Returns [`Error::InvalidSignature`] if signature bytes are invalid.
    pub fn verify_at_time(&self, kid_document: &Document, unix_time: u64) -> Result<(), Error> {
        if kid_document.controller_keys.len() > 20 {
            return Err(Error::KeyLimitExceeded);
        }

        if self.kid != kid_document.kid {
            return Err(Error::UnauthorizedManifestSignature);
        }

        if self.valid_from > unix_time + 300 {
            return Err(Error::InvalidValidFrom);
        }
        if let Some(expires) = self.expires_at {
            if unix_time >= expires {
                return Err(Error::ManifestExpired);
            }
        }
        if self.services.len() > 50 {
            return Err(Error::ServiceLimitExceeded);
        }
        for svc in &self.services {
            if svc.id.len() > 256 {
                return Err(Error::StringLengthExceeded("service.id".to_string()));
            }
            if svc.service_type.len() > 256 {
                return Err(Error::StringLengthExceeded(
                    "service.service_type".to_string(),
                ));
            }
            if svc.protocol.len() > 64 {
                return Err(Error::StringLengthExceeded("service.protocol".to_string()));
            }
            if svc.endpoint.len() > crate::LIMITS_KID_MAX_ENDPOINT_BYTES {
                return Err(Error::StringLengthExceeded("service.endpoint".to_string()));
            }
        }

        let sig_b64 = self.signature.as_ref().ok_or(Error::MissingSignature)?;
        let sig_bytes = b64_url.decode(sig_b64)?;

        let msg_str = self.canonicalize()?;
        let mut msg_bytes = b"kinetic-manifest-v1\0".to_vec();
        msg_bytes.extend_from_slice(msg_str.as_bytes());

        for key in &kid_document.controller_keys {
            if key.key_type.eq_ignore_ascii_case("MlDsa65")
                || key.key_type.eq_ignore_ascii_case("ML-DSA-65")
            {
                if let Ok(pubkey_bytes) = b64_url.decode(&key.public_key) {
                    if kinetic_primitives::verify_mldsa(&pubkey_bytes, &msg_bytes, &sig_bytes)
                        .is_ok()
                    {
                        return Ok(());
                    }
                }
            }
        }

        Err(Error::UnauthorizedManifestSignature)
    }

    /// Helper to sign the manifest with an ML-DSA-65 keypair and return the signed manifest.
    ///
    /// # Errors
    ///
    /// - Returns [`Error::CanonicalizationError`] if JCS canonicalization fails.
    pub fn sign(
        mut self,
        keypair: &kinetic_primitives::keys::KineticKeypair,
    ) -> Result<Self, Error> {
        let msg_str = self.canonicalize()?;
        let mut msg_bytes = b"kinetic-manifest-v1\0".to_vec();
        msg_bytes.extend_from_slice(msg_str.as_bytes());
        let signature_bytes = keypair.sign(&msg_bytes);
        self.signature = Some(b64_url.encode(signature_bytes));
        Ok(self)
    }
}
