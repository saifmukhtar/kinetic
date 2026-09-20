use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as b64_url};

use serde::{Deserialize, Serialize};

use crate::did::Did;
use crate::error::Error;

/// An active verification key authorized to act on behalf of the identity.
///
/// Controller keys are considered "hot" keys. They are used in daily operations
/// to sign `Manifest`s, authorize the rotation of existing keys, and
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

/// A pointer from a [`Document`] to a published [`Manifest`](crate::manifest::Manifest).
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
/// Identifies a Kinetic user and binds their `ControllerPrivKey` public keys to a
/// decentralized identifier. The document is signed with the controller key.
///
/// # Security Architecture (Hot vs Cold Keys)
/// This document enforces a strict separation of privileges:
/// - **Controller Keys (Hot):** Used for standard updates, key rotations, and signing manifests.
/// - **Revocation Keys (Cold):** Kept fully offline. They are cryptographically restricted 
///   to a single action: authorizing a `deactivated: true` document to permanently burn the identity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Document {
    #[serde(rename = "type")]
    /// Schema type tag; always `"kinetic.kid.v1"` for v1 documents.
    pub doc_type: String,
    /// The `did:kin:<hash>` identifier for this document.
    pub kid: Did,
    /// Unix timestamp (seconds) when this document was created.
    pub created_at: u64,
    /// Ordered list of ML-DSA-65 verification keys that control this DID.
    #[serde(deserialize_with = "crate::bounded::deserialize_max_20")]
    pub controller_keys: Vec<ControllerKey>,
    /// Optional pointer to a [`Manifest`](crate::manifest::Manifest).
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

impl Document {
    /// Returns the canonical JCS (RFC 8785) serialization of the document without the signature field.
    ///
    /// # Security
    /// JCS Canonicalization is mandatory. It ensures that arbitrary JSON formatting 
    /// (whitespace, key ordering) by different network peers does not alter the underlying 
    /// byte representation, which would otherwise invalidate the cryptographic signature.
    ///
    /// # Errors
    /// - Returns [`Error::CanonicalizationError`] if JSON serialization fails.
    pub fn canonicalize(&self) -> Result<String, Error> {
        let mut unsigned_doc = self.clone();
        unsigned_doc.signature = None; // Omit signature for canonicalization

        serde_jcs::to_string(&unsigned_doc).map_err(|e| Error::CanonicalizationError(e.to_string()))
    }

    /// Verifies the signature of the document against listed controller or revocation keys.
    ///
    /// # Errors
    /// - Returns [`Error::KeyLimitExceeded`] if controller or revocation key count bounds are exceeded.
    /// - Returns [`Error::LocationLimitExceeded`] if manifest location bounds are exceeded.
    /// - Returns [`Error::StringLengthExceeded`] if any identifier or url string is too long.
    /// - Returns [`Error::MissingSignature`] if the signature field is absent.
    /// - Returns [`Error::Base64Error`] if signature base64url decoding fails.
    /// - Returns [`Error::InvalidSignature`] if no listed key produces a valid cryptographic signature.
    ///
    /// # Examples
    /// ```rust
    /// use kinetic_kid::{Document, Did, ControllerKey};
    /// use kinetic_primitives::kinetic_keypair::ControllerPrivKey;
    /// use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as b64_url};
    /// 
    /// let controller_key = ControllerPrivKey::generate();
    /// let pubkey_b64 = b64_url.encode(controller_key.to_pubkey().as_bytes());
    /// 
    /// // Generate genesis DID
    /// let hash = kinetic_primitives::sha256_hash(controller_key.to_pubkey().as_bytes());
    /// let hex_hash = hash.iter().map(|b| format!("{:02x}", b)).collect::<String>();
    /// let did = Did::new(&format!("did:kin:{}", hex_hash)).unwrap();
    ///
    /// let doc = Document {
    ///     doc_type: "kinetic.kid.v1".to_string(),
    ///     kid: did.clone(),
    ///     created_at: 1000,
    ///     controller_keys: vec![ControllerKey {
    ///         id: format!("{}#primary", did.as_str()),
    ///         key_type: "MlDsa65".to_string(),
    ///         public_key: pubkey_b64,
    ///     }],
    ///     manifest: None,
    ///     revocation_keys: vec![],
    ///     deactivated: false,
    ///     signature: None,
    /// };
    /// 
    /// let signed_doc = doc.sign_with_controller(&controller_key).unwrap();
    /// assert!(signed_doc.verify().is_ok());
    /// assert!(signed_doc.verify_genesis().is_ok());
    /// ```
    pub fn verify(&self) -> Result<(), Error> {
        if self.controller_keys.len() > 20 || self.revocation_keys.len() > 20 {
            return Err(Error::KeyLimitExceeded);
        }
        for key in &self.controller_keys {
            if key.id.len() > 256 {
                return Err(Error::StringLengthExceeded("controller_key.id".to_string()));
            }
            if key.public_key.len() > crate::LIMITS_KID_MAX_PUBLIC_KEY_BYTES {
                return Err(Error::StringLengthExceeded(
                    "controller_key.public_key".to_string(),
                ));
            }
            if key.key_type.len() > 32 {
                return Err(Error::StringLengthExceeded(
                    "controller_key.key_type".to_string(),
                ));
            }
        }
        for rk in &self.revocation_keys {
            if rk.len() > crate::LIMITS_KID_MAX_PUBLIC_KEY_BYTES {
                return Err(Error::StringLengthExceeded(
                    "revocation_keys.item".to_string(),
                ));
            }
        }
        if let Some(manifest) = &self.manifest {
            if manifest.locations.len() > 20 {
                return Err(Error::LocationLimitExceeded);
            }
            for loc in &manifest.locations {
                if loc.len() > crate::LIMITS_KID_MAX_LOCATION_BYTES {
                    return Err(Error::StringLengthExceeded("manifest.location".to_string()));
                }
            }
            if let Some(hash) = &manifest.hash
                && hash.len() > 256
            {
                return Err(Error::StringLengthExceeded("manifest.hash".to_string()));
            }
        }

        let sig_b64 = self.signature.as_ref().ok_or(Error::MissingSignature)?;
        let sig_bytes = b64_url.decode(sig_b64)?;

        let msg_str = self.canonicalize()?;
        
        // ARCHITECTURE NOTE: We intentionally inject the namespace prefix (NSP) as the domain
        // separator rather than the 32-byte `NETWORK_SALT`. KIDs are Layer 2 identities and 
        // are meant to be seamlessly portable between Mainnet and Testnet (which share the same NSP).
        // Using the NSP ensures identity signatures remain portable, while mathematically isolating 
        // them from completely different network forks (e.g. if a private network uses nsp "corp").
        let mut msg_bytes = format!("{}-kid-v1\0", env!("KINETIC_NSP")).into_bytes();
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
                if let Ok(pubkey_bytes) = b64_url.decode(rk_b64)
                    && kinetic_primitives::verify_keypair(&pubkey_bytes, &msg_bytes, &sig_bytes)
                        .is_ok()
                {
                    return Ok(());
                }
            }
        } else {
            // Document is active, the signature MUST be from a controller key
            for key in &self.controller_keys {
                if (key.key_type.eq_ignore_ascii_case("MlDsa65")
                    || key.key_type.eq_ignore_ascii_case("ML-DSA-65"))
                    && let Ok(pubkey_bytes) = b64_url.decode(&key.public_key)
                    && kinetic_primitives::verify_keypair(&pubkey_bytes, &msg_bytes, &sig_bytes)
                        .is_ok()
                {
                    return Ok(());
                }
            }
        }

        Err(Error::InvalidSignature)
    }

    /// Verifies the cryptographic genesis binding: that the DID
    /// is the SHA-256 hash of the primary (first) controller key's raw public bytes.
    ///
    /// # Consensus Rule
    /// This check MUST be executed by the local `kinetic-daemon` **only** during the 
    /// very first publication (genesis) of a KID document. It cryptographically proves 
    /// the creator controls the key that generated the DID. It must **NOT** be called 
    /// on subsequent updates, because authorized key rotation will change the controller 
    /// keys while the DID remains static.
    ///
    /// # Errors
    /// - Returns [`Error::InvalidSignature`] if the document has no controller keys.
    /// - Returns [`Error::Base64Error`] if the primary key is not valid Base64url.
    /// - Returns [`Error::DidKeyMismatch`] if the DID hex suffix does not precisely match
    ///   `hex(SHA-256(primary_controller_key_bytes))`.
    pub fn verify_genesis(&self) -> Result<(), Error> {
        use std::fmt::Write as FmtWrite;

        let primary_key = self
            .controller_keys
            .first()
            .ok_or(Error::InvalidSignature)?;

        let pubkey_bytes = b64_url.decode(&primary_key.public_key)?;
        let hash = kinetic_primitives::sha256_hash(&pubkey_bytes);

        let mut expected_hex = String::with_capacity(64);
        for byte in hash {
            let _ = write!(expected_hex, "{:02x}", byte);
        }
        let expected_kid = format!("{}{}", env!("KINETIC_DID_PREFIX"), expected_hex);

        if self.kid.as_str() != expected_kid {
            return Err(Error::DidKeyMismatch);
        }

        Ok(())
    }

    /// Checks whether `self` (the incoming updated document) was signed by a key
    /// that appeared in `previous_doc` (the currently stored document).
    ///
    /// # Security
    /// This is the core mechanism for secure key rotation. By validating the new document's 
    /// signature against the *old* document's authorized keys, the network maintains an 
    /// unbroken cryptographic chain of custody.
    ///
    /// # Returns
    /// `true` if the update is authorised by a prior controller key, `false` otherwise.
    pub fn is_authorized(&self, previous_doc: &Document) -> bool {
        let sig_b64 = match self.signature.as_ref() {
            Some(s) => s,
            None => return false,
        };

        let sig_bytes = match b64_url.decode(sig_b64) {
            Ok(b) => b,
            Err(_) => return false,
        };

        let msg_str = match self.canonicalize() {
            Ok(s) => s,
            Err(_) => return false,
        };
        // ARCHITECTURE NOTE: We use the NSP rather than NETWORK_SALT to preserve 
        // identity portability between Mainnet/Testnet while isolating private forks.
        let mut msg_bytes = format!("{}-kid-v1\0", env!("KINETIC_NSP")).into_bytes();
        msg_bytes.extend_from_slice(msg_str.as_bytes());

        // Normal path: check if signed by an existing hot key
        let mut authorized = previous_doc.controller_keys.iter().any(|ck| {
            if !ck.key_type.eq_ignore_ascii_case("MlDsa65")
                && !ck.key_type.eq_ignore_ascii_case("ML-DSA-65")
            {
                return false;
            }
            if let Ok(pubkey_bytes) = b64_url.decode(&ck.public_key) {
                return kinetic_primitives::verify_keypair(&pubkey_bytes, &msg_bytes, &sig_bytes)
                    .is_ok();
            }
            false
        });

        // Revocation path: If not authorized by a hot key, and the incoming update
        // explicitly sets deactivated = true, check if authorized by a cold key.
        if !authorized && self.deactivated {
            authorized = previous_doc.revocation_keys.iter().any(|rk_b64| {
                if let Ok(pubkey_bytes) = b64_url.decode(rk_b64) {
                    return kinetic_primitives::verify_keypair(&pubkey_bytes, &msg_bytes, &sig_bytes).is_ok();
                }
                false
            });
        }

        authorized
    }

    /// Signs the document with an ML-DSA-65 signing keypair and populates the Base64url signature field.
    ///
    /// # Errors
    ///
    /// - Returns [`Error::CanonicalizationError`] if JCS canonicalization fails.
    pub fn sign_with_controller(
        mut self,
        key: &kinetic_primitives::kinetic_keypair::ControllerPrivKey,
    ) -> Result<Self, Error> {
        let msg_str = self.canonicalize()?;
        // ARCHITECTURE NOTE: We use the NSP rather than NETWORK_SALT to preserve 
        // identity portability between Mainnet/Testnet while isolating private forks.
        let mut msg_bytes = format!("{}-kid-v1\0", env!("KINETIC_NSP")).into_bytes();
        msg_bytes.extend_from_slice(msg_str.as_bytes());
        let signature_bytes = key.sign(&msg_bytes);
        self.signature = Some(b64_url.encode(signature_bytes));
        Ok(self)
    }

    /// Signs the document with a highly-secure Revocation key.
    /// Used exclusively when permanently deactivating the document.
    pub fn sign_with_revoke(
        mut self,
        key: &kinetic_primitives::kinetic_keypair::RevokePrivKey,
    ) -> Result<Self, Error> {
        let msg_str = self.canonicalize()?;
        // ARCHITECTURE NOTE: We use the NSP rather than NETWORK_SALT to preserve 
        // identity portability between Mainnet/Testnet while isolating private forks.
        let mut msg_bytes = format!("{}-kid-v1\0", env!("KINETIC_NSP")).into_bytes();
        msg_bytes.extend_from_slice(msg_str.as_bytes());
        let signature_bytes = key.sign(&msg_bytes);
        self.signature = Some(b64_url.encode(signature_bytes));
        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kinetic_primitives::kinetic_keypair::{ControllerPrivKey, RevokePrivKey};

    #[test]
    fn test_kid_document_lifecycle() {
        let controller_key = ControllerPrivKey::generate();
        let revocation_key = RevokePrivKey::generate();

        let controller_pub_b64 = b64_url.encode(controller_key.to_pubkey().as_bytes());
        let revocation_pub_b64 = b64_url.encode(revocation_key.to_pubkey().as_bytes());

        let hash = kinetic_primitives::sha256_hash(controller_key.to_pubkey().as_bytes());
        let mut hex_hash = String::new();
        for byte in hash {
            use std::fmt::Write;
            let _ = write!(&mut hex_hash, "{:02x}", byte);
        }
        let did_str = format!("did:kin:{}", hex_hash);

        // 1. Genesis (Create Document)
        let doc = Document {
            doc_type: "kinetic.kid.v1".to_string(),
            kid: Did::new(&did_str).unwrap(),
            created_at: 1000,
            controller_keys: vec![ControllerKey {
                id: format!("{}#primary", did_str),
                key_type: "MlDsa65".to_string(),
                public_key: controller_pub_b64,
            }],
            manifest: None,
            revocation_keys: vec![revocation_pub_b64],
            deactivated: false,
            signature: None,
        };

        // Genesis doc is signed by its own primary controller key
        let signed_genesis = doc.sign_with_controller(&controller_key).unwrap();
        assert!(signed_genesis.verify().is_ok(), "Genesis document verification failed");

        let mut deactivation_update = signed_genesis.clone();
        deactivation_update.deactivated = true;
        deactivation_update.signature = None;
        
        let signed_deactivation = deactivation_update.sign_with_revoke(&revocation_key).unwrap();

        assert!(
            signed_deactivation.verify().is_ok(),
            "Deactivated document failed internal verification when signed by revocation key"
        );

        assert!(
            signed_deactivation.is_authorized(&signed_genesis),
            "Network authorization failed for revocation update signed by revocation key"
        );

        let unauthorized_key = RevokePrivKey::generate();
        let mut unauthorized_update = signed_genesis.clone();
        unauthorized_update.deactivated = true;
        unauthorized_update.signature = None;
        let signed_unauthorized = unauthorized_update.sign_with_revoke(&unauthorized_key).unwrap();
        
        assert!(
            !signed_unauthorized.is_authorized(&signed_genesis),
            "Network authorized a deactivation from an unknown key"
        );
    }
}
