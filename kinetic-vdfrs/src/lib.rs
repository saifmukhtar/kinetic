#![allow(rustdoc::redundant_explicit_links)]
//! # kinetic-vdfrs
//!
//! A pure Rust implementation of the Verifiable Delay Function (VDF) verifier for the Kinetic network.
//!
//! Unlike `kinetic-vdf` which relies on the C++ `chiavdf` library and `libgmp`,
//! this crate acts as a thin wrapper over the `kyn-vdf` crate to evaluate Class Group operations.
//! `kyn-vdf` provides a pure Rust, zero-FFI implementation (using `num-bigint`).
//! This allows VDF proofs to be securely verified in `wasm32-unknown-unknown` environments,
//! enabling Light Nodes in web browsers and mobile apps to achieve zero-trust data verification.

#![deny(missing_docs)]

use kinetic_core::error::VdfError;
use kinetic_core::traits::VdfEngine;
use kinetic_core::types::{Commitment, VdfProof};

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
        kyn_vdf::verify_chia_vdf(&challenge.hash, &proof.proof_bytes, iterations, 1024)
            .map_err(|_| VdfError::InvalidProof)
    }
}

