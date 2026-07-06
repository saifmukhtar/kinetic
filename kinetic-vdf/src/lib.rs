//! # kinetic-vdf
//!
//! Verifiable Delay Function (VDF) implementation for the Kinetic network,
//! wrapping the [`chiavdf`](https://crates.io/crates/chiavdf) library.
//!
//! A VDF is a function that takes a predictable, sequential amount of time to
//! compute, but whose result can be verified almost instantly. Kinetic uses it
//! to enforce time-locked grace periods on domain transfers, preventing
//! domain sniping and hostile takeovers.
//!
//! The `kinetic-vdf` crate provides concrete implementations of the
//! [`VdfEngine`] trait defined in `kinetic-core`.
//!
//! It primarily uses the `chiavdf` C++ engine (via the `chiavdf` Rust bindings).
//! On Android, both `evaluate` and `verify` return
//! [`VdfError::UnsupportedPlatform`] because native compilation of chiavdf is
//! not supported in that environment.
//!
//! A filesystem lock (`/tmp/kinetic_vdf.lock`) is acquired before each
//! evaluation to prevent concurrent VDF computations from saturating all CPU
//! cores simultaneously.

#![deny(missing_docs)]

use kinetic_core::error::VdfError;
use kinetic_core::traits::VdfEngine;
use kinetic_core::types::{Commitment, VdfProof};

/// A Rust wrapper around the external `chiavdf` library.
pub struct ChiaVdfEngine;

impl ChiaVdfEngine {
    /// Creates a new [`ChiaVdfEngine`] instance.
    pub fn new() -> Self {
        Self
    }

    /// Returns the default class group identity element used by chiavdf.
    fn default_element() -> [u8; 100] {
        let mut default_el = [0; 100];
        default_el[0] = 0x08;
        default_el
    }
}

impl Default for ChiaVdfEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(not(target_os = "android"))]
impl VdfEngine for ChiaVdfEngine {
    fn evaluate(&self, challenge: &Commitment, iterations: u64) -> Result<VdfProof, VdfError> {
        // Acquire an exclusive system-wide lock to prevent concurrent VDF
        // evaluations from starving all CPU cores simultaneously.
        use fs2::FileExt;
        let lock_path = std::env::temp_dir().join("kinetic_vdf.lock");
        let lock_file = std::fs::File::create(&lock_path)
            .map_err(|e| VdfError::LockFileError(e.to_string()))?;

        lock_file
            .lock_exclusive()
            .map_err(|e| VdfError::LockAcquireError(e.to_string()))?;

        // chiavdf requires a 1024-bit discriminant derived from the challenge hash.

        let default_el = Self::default_element();

        let result = match chiavdf::prove(&challenge.hash, &default_el, 1024, iterations) {
            Some(proof_bytes) => Ok(VdfProof { proof_bytes }),
            None => Err(VdfError::ProofGenerationError),
        };

        // Lock file is released automatically when it goes out of scope here.
        result
    }

    fn verify(
        &self,
        challenge: &Commitment,
        proof: &VdfProof,
        iterations: u64,
    ) -> Result<bool, VdfError> {
        let mut disc = [0u8; 128];
        if !chiavdf::create_discriminant(&challenge.hash, &mut disc) {
            return Err(VdfError::DiscriminantError);
        }

        let default_el = Self::default_element();

        let is_valid = chiavdf::verify_n_wesolowski(
            &disc,
            &default_el,
            &proof.proof_bytes,
            iterations,
            0, // Recursion limit
        );

        Ok(is_valid)
    }
}

#[cfg(target_os = "android")]
impl VdfEngine for ChiaVdfEngine {
    fn evaluate(&self, _challenge: &Commitment, _iterations: u64) -> Result<VdfProof, VdfError> {
        Err(VdfError::UnsupportedPlatform)
    }

    fn verify(
        &self,
        _challenge: &Commitment,
        _proof: &VdfProof,
        _iterations: u64,
    ) -> Result<bool, VdfError> {
        Err(VdfError::UnsupportedPlatform)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kinetic_core::types::Commitment;

    #[test]
    fn test_vdf_prove_and_verify() {
        let engine = ChiaVdfEngine::new();
        let challenge = Commitment { hash: [1u8; 32] };
        // Small iteration count keeps the test fast while still exercising real chiavdf logic.
        let iterations = 1000;

        let proof = engine.evaluate(&challenge, iterations).unwrap();
        assert!(!proof.proof_bytes.is_empty());

        let is_valid = engine.verify(&challenge, &proof, iterations).unwrap();
        assert!(is_valid);

        let invalid_proof = VdfProof {
            proof_bytes: vec![],
        };
        let is_invalid = engine
            .verify(&challenge, &invalid_proof, iterations)
            .unwrap();
        assert!(!is_invalid);
    }
}
