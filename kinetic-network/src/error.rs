//! Fine-grained error codes for the Kademlia record store.
//! Replaces the single overloaded `kad::store::Error::ValueTooLarge`
//! previously returned for 19+ completely different rejection reasons.

use kinetic_core::error::Severity;
use thiserror::Error;

#[derive(Error, Debug, Clone)]
pub enum KineticStoreError {
    #[error("payload exceeds maximum size limit")]
    PayloadTooLarge,
    #[error("VDF proof has expired ({age} rounds old)")]
    VdfExpired { age: u64 },
    #[error("VDF proof is invalid")]
    InvalidVdf,
    #[error("VDF engine returned an error: {0}")]
    VdfEngineError(String),
    #[error("signature verification failed")]
    InvalidSignature,
    #[error("public key bytes are malformed")]
    InvalidPublicKey,
    #[error("signature bytes are malformed")]
    MalformedSignature,
    #[error("name is currently hibernating")]
    Hibernating,
    #[error("lost the XOR tie-break against an existing record")]
    TieBroken,
    #[error("insufficient VDF iterations to steal this name")]
    InsufficientIterations,
    #[error("no existing reveal found for this name")]
    RevealNotFound,
    #[error("KID document signature is invalid")]
    InvalidKidSignature,
    #[error("manifest proof-of-work is invalid")]
    InvalidManifestPoW,
    #[error("unknown record type prefix")]
    UnknownRecordType,
    #[error("drand_randomness field contains invalid hex")]
    InvalidDrandHex,
}

impl KineticStoreError {
    pub fn severity(&self) -> Severity {
        match self {
            Self::TieBroken
            | Self::InsufficientIterations
            | Self::Hibernating
            | Self::VdfExpired { .. }
            | Self::RevealNotFound => Severity::Info,
            Self::PayloadTooLarge | Self::UnknownRecordType => Severity::Warning,
            Self::InvalidVdf
            | Self::InvalidSignature
            | Self::InvalidPublicKey
            | Self::MalformedSignature
            | Self::VdfEngineError(_)
            | Self::InvalidKidSignature
            | Self::InvalidManifestPoW
            | Self::InvalidDrandHex => Severity::Error,
        }
    }
}

// Map to the libp2p expected error type.
// The specific KineticStoreError is logged before this conversion is made.
impl From<KineticStoreError> for libp2p::kad::store::Error {
    fn from(_e: KineticStoreError) -> Self {
        libp2p::kad::store::Error::ValueTooLarge
    }
}
