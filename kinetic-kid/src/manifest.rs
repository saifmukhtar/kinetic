use base64::{engine::general_purpose::URL_SAFE_NO_PAD as b64_url, Engine};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
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
    /// Unix timestamp (seconds) from which this manifest is considered valid.
    pub valid_from: u64,
    /// PoW nonce satisfying the 20-bit difficulty target.
    pub pow_nonce: u64,
    /// Ordered list of service endpoints this DID owner is advertising.
    pub services: Vec<ServiceEntry>,
    /// Base64url-encoded Ed25519 signature over the JCS-canonical manifest (excluding this field).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

impl CapabilityManifest {
    /// Returns the canonical JCS serialization of the manifest without the signature.
    pub fn canonicalize(&self) -> Result<String, KidError> {
        let mut unsigned_manifest = self.clone();
        unsigned_manifest.signature = None; // Omit signature for canonicalization

        serde_jcs::to_string(&unsigned_manifest)
            .map_err(|e| KidError::CanonicalizationError(e.to_string()))
    }

    /// Verifies the signature of the manifest using the authorized controller keys in the provided KID Document.
    pub fn verify(&self, kid_document: &KidDocument) -> Result<(), KidError> {
        if self.kid != kid_document.kid {
            return Err(KidError::UnauthorizedManifestSignature);
        }

        let sig_b64 = self.signature.as_ref().ok_or(KidError::MissingSignature)?;
        let sig_bytes = b64_url.decode(sig_b64)?;

        if sig_bytes.len() != 64 {
            return Err(KidError::InvalidSignature);
        }
        let signature = Signature::from_bytes(sig_bytes.as_slice().try_into().unwrap());

        let msg_str = self.canonicalize()?;
        let msg_bytes = msg_str.as_bytes();

        use sha2::{Digest, Sha256};
        let mut pow_hasher = Sha256::new();
        pow_hasher.update(msg_bytes);
        let mut pow_hash = [0u8; 32];
        pow_hash.copy_from_slice(&pow_hasher.finalize());
        if !cfg!(feature = "simulation")
            && !crate::validate_pow(&pow_hash, crate::KID_POW_TARGET)
        {
            return Err(KidError::CanonicalizationError(
                "Invalid Proof of Work".to_string(),
            ));
        }

        for key in &kid_document.controller_keys {
            if key.key_type == "Ed25519" {
                if let Ok(pk_bytes) = b64_url.decode(&key.public_key) {
                    if let Ok(pk_array) = pk_bytes.as_slice().try_into() {
                        if let Ok(public_key) = VerifyingKey::from_bytes(pk_array) {
                            if public_key.verify(msg_bytes, &signature).is_ok() {
                                return Ok(());
                            }
                        }
                    }
                }
            }
        }

        Err(KidError::UnauthorizedManifestSignature)
    }

    /// Helper to sign the manifest with a given keypair and return the signed manifest.
    pub fn sign(mut self, keypair: &ed25519_dalek::SigningKey) -> Result<Self, KidError> {
        use ed25519_dalek::Signer;
        let msg_str = self.canonicalize()?;
        let signature = keypair.sign(msg_str.as_bytes());
        self.signature = Some(b64_url.encode(signature.to_bytes()));
        Ok(self)
    }

    /// Mines a valid pow_nonce for this manifest. Should be called BEFORE sign().
    pub fn mine_pow(&mut self) {
        if cfg!(feature = "simulation") {
            self.pow_nonce = 0;
            return;
        }
        use sha2::{Digest, Sha256};
        let mut nonce = 0u64;
        loop {
            self.pow_nonce = nonce;
            if let Ok(msg_str) = self.canonicalize() {
                let mut hasher = Sha256::new();
                hasher.update(msg_str.as_bytes());
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&hasher.finalize());
                if crate::validate_pow(&hash, crate::KID_POW_TARGET) {
                    break;
                }
            }
            nonce += 1;
        }
    }

    /// Verifies the Proof of Work (PoW) independently.
    pub fn verify_pow(&self) -> bool {
        if cfg!(feature = "simulation") {
            return true;
        }
        use sha2::{Digest, Sha256};
        if let Ok(msg_str) = self.canonicalize() {
            let mut hasher = Sha256::new();
            hasher.update(msg_str.as_bytes());
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&hasher.finalize());
            return crate::validate_pow(&hash, crate::KID_POW_TARGET);
        }
        false
    }
}
