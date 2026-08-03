#![allow(rustdoc::redundant_explicit_links)]
//! # kinetic-vdfrs
//!
//! A pure Rust implementation of the Verifiable Delay Function (VDF) verifier for the Kinetic network.
//!
//! Unlike `kinetic-vdf` which relies on the C++ `chiavdf` library and `libgmp`,
//! this crate uses pure Rust math (`num-bigint`) to evaluate Class Group operations.
//! This allows VDF proofs to be securely verified in `wasm32-unknown-unknown` environments,
//! enabling Light Nodes in web browsers and mobile apps to achieve zero-trust data verification.

#![deny(missing_docs)]

/// Mathematical primitives for Imaginary Quadratic Class Groups.
pub mod math;

/// Chia discriminant generation, serialization, and Wesolowski verification primitives.
pub mod chia;

use kinetic_core::error::VdfError;
use kinetic_core::traits::VdfEngine;
use kinetic_core::types::{Commitment, VdfProof};
use math::Form;

/// A pure Rust VDF Engine designed specifically for Wasm Light Node verification.
pub struct PureRustVdfEngine;

impl PureRustVdfEngine {
    /// Creates a new [`PureRustVdfEngine`] instance.
    pub fn new() -> Self {
        Self
    }
}

impl Default for PureRustVdfEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl VdfEngine for PureRustVdfEngine {
    /// Evaluates a Verifiable Delay Function.
    ///
    /// # Errors
    ///
    /// This pure Rust implementation does not support proof *generation*, as doing so without
    /// heavily optimized assembly is too slow. It always returns [`VdfError::UnsupportedPlatform`].
    /// Proof generation is strictly for Full Nodes using `chiavdf`.
    fn evaluate(&self, _challenge: &Commitment, _iterations: u64) -> Result<VdfProof, VdfError> {
        // Only Full Nodes generate proofs.
        Err(VdfError::UnsupportedPlatform)
    }

    /// Verifies a Wesolowski VDF proof.
    ///
    /// # Errors
    ///
    /// Returns a [`VdfError`] if the proof is malformed or invalid.
    fn verify(
        &self,
        challenge: &Commitment,
        proof: &VdfProof,
        iterations: u64,
    ) -> Result<bool, VdfError> {
        if iterations == 0 {
            return Err(VdfError::InvalidProof);
        }
        if proof.proof_bytes.len() != 200 {
            return Err(VdfError::InvalidProof);
        }

        // 1. Derive 1024-bit prime discriminant D = -p
        let d = chia::create_discriminant(&challenge.hash, 1024);

        // 2. Generator element x = (2, 1, (1 - D)/8)
        let x = Form::generator(&d).ok_or(VdfError::DiscriminantError)?;

        // 3. Deserialize target form y (first 100 bytes) and proof form pi (second 100 bytes)
        let y = chia::deserialize_form(&d, &proof.proof_bytes[0..100])
            .map_err(|_| VdfError::InvalidProof)?;
        let pi = chia::deserialize_form(&d, &proof.proof_bytes[100..200])
            .map_err(|_| VdfError::InvalidProof)?;

        // 4. Verify Wesolowski proof: pi^B * x^r == y
        chia::verify_wesolowski(&d, &x, &y, &pi, iterations)
            .map_err(|_| VdfError::InvalidProof)
    }

}

