use serde::{Deserialize, Serialize};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as b64_url, Engine};
use ed25519_dalek::{VerifyingKey, Signature, Verifier};

use crate::did::KineticDid;
use crate::error::KidError;
use crate::document::KidDocument;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServiceEntry {
    pub id: String,
    #[serde(rename = "type")]
    pub service_type: String, // e.g., "website", "api"
    pub protocol: String,     // e.g., "https", "grpc"
    pub endpoint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapabilityManifest {
    #[serde(rename = "type")]
    pub doc_type: String, // Expected to be "kinetic.manifest.v1"
    pub kid: KineticDid,
    pub version: u64,
    pub valid_from: u64,
    pub services: Vec<ServiceEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>, // Base64url encoded
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

        for key in &kid_document.controller_keys {
            if key.key_type == "Ed25519" {
                if let Ok(pk_bytes) = b64_url.decode(&key.public_key) {
                    if let Ok(public_key) = VerifyingKey::from_bytes(pk_bytes.as_slice().try_into().unwrap()) {
                        if public_key.verify(msg_bytes, &signature).is_ok() {
                            return Ok(());
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
}
