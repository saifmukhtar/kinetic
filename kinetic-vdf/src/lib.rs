#![allow(rustdoc::redundant_explicit_links)]
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
    /// Evaluates a Verifiable Delay Function for a given challenge and iteration count.
    ///
    /// # Errors
    ///
    /// - Returns [`VdfError::ProofGenerationError`](kinetic_core::error::VdfError::ProofGenerationError) (`KIN-VDF-004`) if `iterations > 400_000_000_000` or chiavdf fails.
    /// - Returns [`VdfError::LockFileError`](kinetic_core::error::VdfError::LockFileError) (`KIN-VDF-001`) if the system lock file cannot be created.
    /// - Returns [`VdfError::LockAcquireError`](kinetic_core::error::VdfError::LockAcquireError) (`KIN-VDF-002`) if acquiring exclusive lock fails.
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
            #[cfg(unix)]
            {
                let uid = unsafe { libc::getuid() };
                lock_dir = std::env::temp_dir().join(format!("kinetic-{}", uid));
                if let Err(e) = std::fs::create_dir_all(&lock_dir) {
                    return Err(VdfError::LockFileError(format!(
                        "Failed to create fallback lock dir: {}",
                        e
                    )));
                }
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&lock_dir, std::fs::Permissions::from_mode(0o700));
            }
            #[cfg(not(unix))]
            {
                lock_dir = std::env::temp_dir().join(format!("kinetic-{}", std::process::id()));
                let _ = std::fs::create_dir_all(&lock_dir);
            }
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

    /// Verifies a Wesolowski VDF proof against the target commitment and iteration count.
    ///
    /// # Errors
    ///
    /// - Returns [`VdfError::InvalidProof`](kinetic_core::error::VdfError::InvalidProof) (`KIN-VDF-006`) if `proof.proof_bytes.len() > 1024`.
    /// - Returns [`VdfError::DiscriminantError`](kinetic_core::error::VdfError::DiscriminantError) (`KIN-VDF-003`) if discriminant derivation fails.
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

        println!("proof length: {}", proof.proof_bytes.len());

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
    fn test_kyn_vdf_verifies_kinetic_proof() {
        let engine = ChiaVdfEngine::new();

        let challenge = Commitment {
            hash: [1u8; 32],
        };

        let iterations = 1000;

        // Generate a real proof using the existing Chia VDF prover.
        let proof = engine
        .evaluate(&challenge, iterations)
        .expect("Kinetic VDF proof generation failed");

        assert_eq!(
            proof.proof_bytes.len(),
                   200,
                   "Kinetic proof must use the 200-byte Chia wire format"
        );

        // Verify the exact same proof using the pure-Rust verifier.
        let is_valid = kyn_vdf::verify_chia_vdf(
            &challenge.hash,
            &proof.proof_bytes,
            iterations,
            1024,
        )
        .expect("kyn-vdf rejected the input as malformed");

        assert!(
            is_valid,
            "kyn-vdf failed to verify a proof generated by chiavdf"
        );
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

    #[test]
    fn test_chiavdf_and_kyn_vdf_differential_compatibility() {
        let engine = ChiaVdfEngine::new();

        // Generate several brand-new proofs. The challenges are deterministic
        // so that any failure can be reproduced exactly.
        let challenges = [
            [0x00u8; 32],
            [0x01u8; 32],
            [0x2au8; 32],
            [0x55u8; 32],
            [0xffu8; 32],
        ];

        // This exercises significantly more sequential work than the existing
        // 1,000-iteration test while remaining practical for normal test runs.
        let iterations = 10_000u64;

        for (index, hash) in challenges.into_iter().enumerate() {
            let challenge = Commitment { hash };

            println!(
                "\n=== Differential VDF test {}/{} ===",
                index + 1,
                challenges.len()
            );

            // ============================================================
            // 1. Generate a completely new proof using the real chiavdf prover.
            // ============================================================
            let proof = engine
            .evaluate(&challenge, iterations)
            .expect("chiavdf failed to generate a proof");

            println!("Generated proof length: {} bytes", proof.proof_bytes.len());

            // Kinetic currently uses the standard Chia y || pi wire format:
            // 100 bytes for y + 100 bytes for pi.
            assert_eq!(
                proof.proof_bytes.len(),
                       200,
                       "unexpected proof length for challenge {:02x?}",
                       challenge.hash
            );

            // ============================================================
            // 2. Verify the new proof using Kinetic's existing chiavdf verifier.
            // ============================================================
            let chiavdf_valid = engine
            .verify(&challenge, &proof, iterations)
            .expect("chiavdf verification returned an error");

            assert!(
                chiavdf_valid,
                "chiavdf rejected its own newly generated proof"
            );

            // ============================================================
            // 3. Verify the exact same proof using pure-Rust kyn-vdf.
            //
            // A genuine proof generated by chiavdf must produce Ok(true).
            // An error here is a real compatibility failure.
            // ============================================================
            let kyn_vdf_valid = kyn_vdf::verify_chia_vdf(
                &challenge.hash,
                &proof.proof_bytes,
                iterations,
                1024,
            )
            .expect("kyn-vdf could not parse a genuine chiavdf-generated proof");

            assert!(
                kyn_vdf_valid,
                "kyn-vdf rejected a genuine proof generated by chiavdf"
            );

            assert_eq!(
                chiavdf_valid,
                kyn_vdf_valid,
                "chiavdf and kyn-vdf disagreed on a valid proof"
            );

            println!("Valid proof: chiavdf=true, kyn-vdf=true");

            // ============================================================
            // 4. Corrupt one bit in the proof.
            //
            // chiavdf returns false for rejection.
            //
            // kyn-vdf can reject in either valid way:
            //   Ok(false) -> parsed successfully but failed mathematics
            //   Err(_)    -> corrupted bytes could not be deserialized
            //
            // Both outcomes mean the corrupted proof was rejected.
            // ============================================================
            let mut corrupted_bytes = proof.proof_bytes.clone();
            corrupted_bytes[50] ^= 0x01;

            let corrupted_proof = VdfProof {
                proof_bytes: corrupted_bytes.clone(),
            };

            let chiavdf_corrupted = engine
            .verify(&challenge, &corrupted_proof, iterations)
            .expect("chiavdf verification returned an unexpected error");

            assert!(
                !chiavdf_corrupted,
                "chiavdf accepted a one-bit-corrupted proof"
            );

            let kyn_vdf_corrupted_rejected = match kyn_vdf::verify_chia_vdf(
                &challenge.hash,
                &corrupted_bytes,
                iterations,
                1024,
            ) {
                Ok(false) => true,
                Ok(true) => false,
                Err(_) => true,
            };

            assert!(
                kyn_vdf_corrupted_rejected,
                "kyn-vdf accepted a one-bit-corrupted proof"
            );

            println!("Corrupted proof: both implementations rejected it");

            // ============================================================
            // 5. Verify with the wrong iteration count.
            //
            // The proof was generated using `iterations`, not
            // `iterations + 1`.
            //
            // For kyn-vdf, Ok(false) and Err(_) are both rejection.
            // ============================================================
            let wrong_iterations = iterations + 1;

            let chiavdf_wrong_iterations = engine
            .verify(&challenge, &proof, wrong_iterations)
            .expect("chiavdf verification returned an unexpected error");

            assert!(
                !chiavdf_wrong_iterations,
                "chiavdf accepted a proof with the wrong iteration count"
            );

            let kyn_vdf_wrong_iterations_rejected =
            match kyn_vdf::verify_chia_vdf(
                &challenge.hash,
                &proof.proof_bytes,
                wrong_iterations,
                1024,
            ) {
                Ok(false) => true,
                Ok(true) => false,
                Err(_) => true,
            };

            assert!(
                kyn_vdf_wrong_iterations_rejected,
                "kyn-vdf accepted a proof with the wrong iteration count"
            );

            println!("Wrong iteration count: both implementations rejected it");

            // ============================================================
            // 6. Verify with a different challenge.
            //
            // A different challenge derives a different discriminant.
            // The original proof must not verify under that discriminant.
            //
            // Again, kyn-vdf may return Ok(false) or Err(_).
            // ============================================================
            let mut wrong_hash = challenge.hash;
            wrong_hash[0] ^= 0x80;

            let wrong_challenge = Commitment {
                hash: wrong_hash,
            };

            let chiavdf_wrong_challenge = engine
            .verify(&wrong_challenge, &proof, iterations)
            .expect("chiavdf verification returned an unexpected error");

            assert!(
                !chiavdf_wrong_challenge,
                "chiavdf accepted a proof for a different challenge"
            );

            let kyn_vdf_wrong_challenge_rejected =
            match kyn_vdf::verify_chia_vdf(
                &wrong_challenge.hash,
                &proof.proof_bytes,
                iterations,
                1024,
            ) {
                Ok(false) => true,
                Ok(true) => false,
                Err(_) => true,
            };

            assert!(
                kyn_vdf_wrong_challenge_rejected,
                "kyn-vdf accepted a proof for a different challenge"
            );

            println!("Wrong challenge: both implementations rejected it");

            // ============================================================
            // 7. Verify with a truncated proof.
            //
            // Kinetic's chiavdf verifier should reject it.
            // kyn-vdf should return an error because the proof is shorter
            // than the required 200-byte Chia wire format.
            // ============================================================
            let truncated_bytes = proof.proof_bytes[..199].to_vec();

            let truncated_proof = VdfProof {
                proof_bytes: truncated_bytes.clone(),
            };

            let chiavdf_truncated = engine
            .verify(&challenge, &truncated_proof, iterations)
            .expect("chiavdf verification returned an unexpected error");

            assert!(
                !chiavdf_truncated,
                "chiavdf accepted a truncated proof"
            );

            let kyn_vdf_truncated_rejected = match kyn_vdf::verify_chia_vdf(
                &challenge.hash,
                &truncated_bytes,
                iterations,
                1024,
            ) {
                Ok(false) => true,
                Ok(true) => false,
                Err(_) => true,
            };

            assert!(
                kyn_vdf_truncated_rejected,
                "kyn-vdf accepted a truncated proof"
            );

            println!("Truncated proof: both implementations rejected it");
        }

        println!(
            "\nSUCCESS: all {} newly generated chiavdf proofs were accepted \
by both verifiers, and all tested invalid variants were rejected.",
challenges.len()
        );
    }
}
