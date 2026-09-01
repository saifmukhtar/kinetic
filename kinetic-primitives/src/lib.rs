//! Core cryptographic primitives for the Kinetic Network.
//!
//! This module centralizes all hashing and Post-Quantum (ML-DSA-65) signature logic
//! to prevent fragmentation across the workspace. It enforces strict typing and
//! canonical implementations of cryptographic operations.

use ml_dsa::signature::Verifier;
use ml_dsa::{KeyInit, MlDsa65};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub mod keys;

/// Centralized error type for cryptographic primitive operations.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// Returned when a signature byte array cannot be decoded or is mathematically invalid.
    #[error("Invalid ML-DSA-65 signature encoding")]
    InvalidSignature,

    /// Returned when a public key byte array is the wrong length or malformed.
    #[error("Invalid ML-DSA-65 public key format")]
    InvalidPublicKey,

    /// Returned when a signature is well-formed but does not match the message.
    #[error("Cryptographic verification failed")]
    VerificationFailed,
}

/// Computes a standard SHA-256 hash and returns exactly 32 bytes.
/// Use this function instead of manually invoking `Sha256::new()`.
pub fn sha256_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Computes a single SHA-256 hash over multiple chunks of data.
/// This avoids allocating intermediate buffers when concatenating data.
pub fn sha256_hash_concat(chunks: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for chunk in chunks {
        hasher.update(*chunk);
    }
    hasher.finalize().into()
}

/// Verifies a post-quantum ML-DSA-65 signature against a given public key and message.
///
/// # Arguments
/// * `pubkey_bytes` - The raw public key bytes to verify against.
/// * `message` - The raw message bytes that were signed.
/// * `signature_bytes` - The raw ML-DSA-65 signature bytes.
///
/// # Errors
/// Returns a `CryptoError` if the public key or signature is malformed,
/// or if the signature does not mathematically match the message.
pub fn verify_mldsa(
    pubkey_bytes: &[u8],
    message: &[u8],
    signature_bytes: &[u8],
) -> Result<(), CryptoError> {
    let pubkey = ml_dsa::VerifyingKey::<MlDsa65>::new_from_slice(pubkey_bytes)
        .map_err(|_| CryptoError::InvalidPublicKey)?;

    let sig = ml_dsa::Signature::<MlDsa65>::try_from(signature_bytes)
        .map_err(|_| CryptoError::InvalidSignature)?;

    pubkey
        .verify(message, &sig)
        .map_err(|_| CryptoError::VerificationFailed)
}
