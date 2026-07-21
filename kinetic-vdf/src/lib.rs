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
//! A filesystem lock (in `dirs::runtime_dir()`) is acquired before each
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
    #[allow(dead_code)]
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

#[cfg(all(not(target_os = "android"), not(target_arch = "wasm32")))]
impl VdfEngine for ChiaVdfEngine {
    fn evaluate(&self, challenge: &Commitment, iterations: u64) -> Result<VdfProof, VdfError> {
        // Bound max iterations to 400 Billion to prevent DoS lock contention (allows up to ~30 days of CPU time)
        if iterations > 400_000_000_000 {
            return Err(VdfError::ProofGenerationError);
        }
        // Acquire an exclusive system-wide lock to prevent concurrent VDF
        // evaluations from starving all CPU cores simultaneously.
        use fs2::FileExt;

        let mut lock_dir = kinetic_core::config::get_base_dir();
        if std::fs::create_dir_all(&lock_dir).is_err() {
            lock_dir = std::env::temp_dir();
        }
        let lock_path = lock_dir.join("kinetic_vdf.lock");

        let mut options = std::fs::OpenOptions::new();
        options.read(true).write(true).create(true);

        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW);
        }

        let lock_file = options
            .open(&lock_path)
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
        if proof.proof_bytes.len() > 1024 {
            // 1 KB sanity check (Wesolowski proofs are small)
            return Err(VdfError::InvalidProof);
        }

        let mut disc = [0u8; 128];
        // Note: Asymmetric Discriminant Derivation
        // `chiavdf::prove` takes the raw challenge hash and derives the 1024-bit
        // discriminant internally. However, `verify_n_wesolowski` expects the
        // derived discriminant to be passed in. Both must derive it identically.
        if !chiavdf::create_discriminant(&challenge.hash, &mut disc) {
            return Err(VdfError::DiscriminantError);
        }

        let default_el = Self::default_element();

        let is_valid = chiavdf::verify_n_wesolowski(
            &disc,
            &default_el,
            &proof.proof_bytes,
            iterations,
            0, // Recursion limit: 0 because we do not use segmented proofs (our proofs are small).
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

#[cfg(target_arch = "wasm32")]
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

    #[test]
    fn test_concurrent_evaluate() {
        use std::sync::Arc;
        use std::thread;

        let engine = Arc::new(ChiaVdfEngine::new());
        let handles: Vec<_> = (0..4)
            .map(|i| {
                let e = engine.clone();
                thread::spawn(move || {
                    let challenge = Commitment {
                        hash: [i as u8; 32],
                    };
                    // Small iteration count, but run concurrently to test lock logic and C++ safety
                    e.evaluate(&challenge, 500).unwrap()
                })
            })
            .collect();

        for h in handles {
            let proof = h.join().unwrap();
            assert!(!proof.proof_bytes.is_empty());
        }
    }

    #[test]
    fn test_max_proof_size_is_sufficient() {
        let engine = ChiaVdfEngine::new();
        let challenge = Commitment { hash: [0u8; 32] };

        // Test different iteration lengths
        for iterations in [100, 1000, 10_000, 100_000] {
            let proof = engine.evaluate(&challenge, iterations).unwrap();
            assert!(
                proof.proof_bytes.len() <= 1024,
                "Proof size {} exceeds MAX_PROOF_SIZE at {} iterations",
                proof.proof_bytes.len(),
                iterations
            );
        }
    }

    #[test]
    fn test_edge_cases() {
        let engine = ChiaVdfEngine::new();
        let challenge = Commitment { hash: [2u8; 32] };
        let proof = engine.evaluate(&challenge, 1000).unwrap();

        // 1. Mismatched iterations
        let is_valid = engine.verify(&challenge, &proof, 2000).unwrap();
        assert!(!is_valid, "Should reject mismatched iterations");

        // 2. Zero iterations - chiavdf might return false or panic. Our engine shouldn't panic.
        let is_valid_zero = engine.verify(&challenge, &proof, 0).unwrap();
        assert!(!is_valid_zero, "Should reject 0 iterations");
    }

    #[test]
    fn test_discriminant_consistency_across_versions() {
        // Ensures discriminant derivation logic hasn't silently changed inside chiavdf
        let challenge = Commitment { hash: [42u8; 32] };
        let mut disc_verify = [0u8; 128];

        let success = chiavdf::create_discriminant(&challenge.hash, &mut disc_verify);
        assert!(success, "Discriminant creation failed");

        // This is the expected discriminant for hash [42u8; 32]
        // If a version bump changes this, it will fail backwards compatibility.
        let expected_prefix = [
            237, 89, 165, 1, 5, 76, 207, 152, 207, 134, 182, 117, 254, 184, 124, 248,
        ];

        assert_eq!(
            &disc_verify[0..16],
            &expected_prefix[..],
            "Discriminant derivation logic changed! This breaks backwards compatibility."
        );
    }
}
