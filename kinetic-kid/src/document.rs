use serde::{Deserialize, Serialize};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as b64_url, Engine};
use ed25519_dalek::{VerifyingKey, Signature, Verifier};

use crate::did::KineticDid;
use crate::error::KidError;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ControllerKey {
    pub id: String,
    #[serde(rename = "type")]
    pub key_type: String, // Expected to be "Ed25519"
    pub public_key: String, // Base64url encoded
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManifestPointer {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub locations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KidDocument {
    #[serde(rename = "type")]
    pub doc_type: String, // Expected to be "kinetic.kid.v1"
    pub kid: KineticDid,
    pub created_at: u64,
    pub controller_keys: Vec<ControllerKey>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manifest: Option<ManifestPointer>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub revocation_keys: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>, // Base64url encoded
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

        for key in &self.controller_keys {
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
