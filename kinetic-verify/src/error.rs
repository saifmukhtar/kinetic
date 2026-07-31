//! Error types for the kinetic-verify crate.

use thiserror::Error;

/// Defines errors that can occur during cryptographic verification.
#[derive(Error, Debug)]
pub enum VerifyError {
    /// The signature failed cryptographic verification (invalid signature).
    #[error("Invalid signature")]
    InvalidSignature,

    /// The public key was malformed or could not be parsed.
    #[error("Malformed public key")]
    MalformedPublicKey,

    /// The signature byte array was malformed or could not be parsed.
    #[error("Malformed signature")]
    MalformedSignature,
}
