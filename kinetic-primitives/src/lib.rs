//! Core cryptographic primitives for the Kinetic Network.
//!
//! This module centralizes all raw hashing and `KineticKeypair` signature logic
//! to prevent fragmentation across the workspace. It enforces strict typing and
//! canonical implementations of cryptographic operations so that higher-level crates
//! do not accidentally misuse raw cryptography libraries.
//!
//! # Architecture Context
//! ```text
//! [kinetic-verify (Consensus Rules)]
//!            |
//!            v
//! [kinetic-primitives::verify_keypair]
//!            |
//!            v
//! [Raw ML-DSA-65 Verification (ml-dsa crate)]
//! ```

use ml_dsa::signature::Verifier;
use ml_dsa::{KeyInit, MlDsa65};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub mod keys;
pub mod kinetic_keypair;

/// Centralized error type for cryptographic primitive operations.
#[derive(Debug, Error)]
pub enum SignatureError {
    /// Returned when a signature byte array cannot be decoded or is mathematically invalid.
    #[error("Invalid ML-DSA-65 signature encoding")]
    InvalidSignature,

    /// Returned when a public key byte array is the wrong length or malformed.
    #[error("Invalid ML-DSA-65 public key format")]
    InvalidPublicKey,

    /// Returned when a signature is well-formed but does not mathematically match the message.
    #[error("Cryptographic verification failed")]
    VerificationFailed,
}

/// Computes a standard SHA-256 hash and returns exactly 32 bytes.
///
/// Use this function instead of manually invoking `Sha256::new()` throughout the workspace
/// to ensure canonical hashing behavior.
///
/// # Examples
/// ```rust
/// use kinetic_primitives::sha256_hash;
///
/// let hash = sha256_hash(b"hello world");
/// assert_eq!(hash.len(), 32);
/// ```
pub fn sha256_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Computes a single SHA-256 hash over multiple chunks of data sequentially.
///
/// This avoids allocating intermediate buffers when you need to hash concatenated data,
/// which is highly beneficial for high-throughput network validation.
///
/// # Examples
/// ```rust
/// use kinetic_primitives::{sha256_hash, sha256_hash_concat};
///
/// let combined = sha256_hash_concat(&[b"hello", b" ", b"world"]);
/// let direct = sha256_hash(b"hello world");
/// assert_eq!(combined, direct);
/// ```
pub fn sha256_hash_concat(chunks: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for chunk in chunks {
        hasher.update(*chunk);
    }
    hasher.finalize().into()
}

/// Verifies a `KineticKeypair` signature against a given public key and message.
///
/// # Security
/// This boundary assumes the caller has already extracted the raw signature bytes 
/// from the network payload. It performs strict mathematical validation but does 
/// **not** check authorization logic (e.g., whether the key is permitted to sign).
///
/// # Arguments
/// * `pubkey_bytes` - The raw public key bytes to verify against.
/// * `message` - The raw message bytes that were signed.
/// * `signature_bytes` - The raw ML-DSA-65 signature bytes.
///
/// # Errors
/// Returns [`SignatureError::InvalidPublicKey`] if the public key bytes are malformed.
/// Returns [`SignatureError::InvalidSignature`] if the signature bytes are malformed.
/// Returns [`SignatureError::VerificationFailed`] if the signature is mathematically invalid.
///
/// # Examples
/// ```rust
/// use kinetic_primitives::keys::KineticKeypair;
/// use kinetic_primitives::verify_keypair;
///
/// let keypair = KineticKeypair::generate();
/// let message = b"consensus payload";
/// let signature = keypair.sign(message);
/// let pubkey = keypair.pubkey_bytes();
///
/// // Verify the signature
/// assert!(verify_keypair(&pubkey, message, &signature).is_ok());
/// ```
pub fn verify_keypair(
    pubkey_bytes: &[u8],
    message: &[u8],
    signature_bytes: &[u8],
) -> Result<(), SignatureError> {
    let pubkey = ml_dsa::VerifyingKey::<MlDsa65>::new_from_slice(pubkey_bytes)
        .map_err(|_| SignatureError::InvalidPublicKey)?;

    let sig = ml_dsa::Signature::<MlDsa65>::try_from(signature_bytes)
        .map_err(|_| SignatureError::InvalidSignature)?;

    pubkey
        .verify(message, &sig)
        .map_err(|_| SignatureError::VerificationFailed)
}
