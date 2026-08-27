//! # kinetic-vdf-rsa
//!
//! A pure Rust implementation of an RSA-based Verifiable Delay Function
//! with Wesolowski's proof of exponentiation, using Blockwise Checkpointing.

pub mod constants;
pub mod hash_to_prime;

use kinetic_core::error::VdfError;
use kinetic_core::traits::VdfEngine;
use kinetic_core::types::{Commitment, VdfProof};
use num_bigint::BigUint;
use num_traits::{One, Zero};
use std::str::FromStr;

/// A pure Rust RSA VDF Engine.
pub struct RsaVdfEngine {
    n: BigUint,
}

impl Default for RsaVdfEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl RsaVdfEngine {
    /// Creates a new `RsaVdfEngine` initialized with the RSA-2048 modulus.
    pub fn new() -> Self {
        let n = BigUint::from_str(constants::RSA_2048_MODULUS_DEC)
            .expect("Hardcoded RSA modulus must be valid");

        Self { n }
    }
}

impl VdfEngine for RsaVdfEngine {
    fn evaluate(&self, challenge: &Commitment, iterations: u64) -> Result<VdfProof, VdfError> {
        let x = BigUint::from_bytes_be(&challenge.hash);
        let mut y = x.clone();
        let n = &self.n;

        // Guard: iterations=0 causes b_block_size=0 and integer division by zero.
        if iterations == 0 {
            return Err(VdfError::InvalidChallenge);
        }

        // Guard: x=0 is a degenerate input where y stays 0 for all squarings,
        // producing a zero proof that verifies against any zero-output challenge.
        // An all-zero Sha256 commitment is astronomically unlikely in practice,
        // but we must reject it explicitly to prevent crafted attacks.
        if x.is_zero() {
            return Err(VdfError::InvalidChallenge);
        }

        y %= n;

        // --- BONEH-BÜNZ-FISCH CHECKPOINTING ---
        // A single 2048-bit BigUint takes exactly 256 bytes.
        // To cap the Prover's memory at ~100MB, we can store a maximum of 300,000 checkpoints.
        let max_checkpoints = 300_000u64;
        let test_block_size = 1_000u64;

        // Dynamically calculate the number of checkpoints (k) based on the iterations.
        let b_block_size = if iterations > max_checkpoints * test_block_size {
            iterations / max_checkpoints
        } else if iterations > test_block_size {
            test_block_size
        } else {
            iterations
        };

        let k = iterations / b_block_size;
        let r_block = iterations % b_block_size;

        let needed_checkpoints = if r_block > 0 { k + 1 } else { k };
        let mut checkpoints = Vec::with_capacity(needed_checkpoints as usize);
        checkpoints.push(y.clone()); // x_0

        // 1. Pass 1: The Delay Loop
        for i in 1..=iterations {
            y = (&y * &y) % n;

            if i % b_block_size == 0 {
                let checkpoint_idx = i / b_block_size;
                if checkpoint_idx < needed_checkpoints {
                    checkpoints.push(y.clone());
                }
            }
        }

        // 2. The Fiat-Shamir Hash
        let l = hash_to_prime::generate_prime_l(&x, &y);

        // 3. Pass 2: Base-2^B Long Division
        let mut q_digits = Vec::with_capacity(needed_checkpoints as usize);
        let mut r = BigUint::one();

        // Handle the remainder block (most significant bits)
        if r_block > 0 {
            let dividend = &r << (r_block as usize);
            let q_i = &dividend / &l;
            r = dividend % &l;
            q_digits.push(q_i);
        }

        for _ in 0..k {
            let dividend = &r << (b_block_size as usize); // r * 2^B
            let q_i = &dividend / &l;
            r = dividend % &l;
            q_digits.push(q_i);
        }

        q_digits.reverse();

        // 4. Pass 3: Simultaneous Multi-Exponentiation
        let mut pi = BigUint::one();

        for bit_idx in (0..b_block_size as u64).rev() {
            pi = (&pi * &pi) % n;

            let mut batch_mult = BigUint::one();
            for i in 0..(k as usize) {
                if q_digits[i].bit(bit_idx) {
                    batch_mult = (batch_mult * &checkpoints[i]) % n;
                }
            }
            pi = (pi * batch_mult) % n;
        }

        // Multiply the remainder block if it exists
        if r_block > 0 {
            let q_rem = &q_digits[k as usize];
            let pi_rem = checkpoints[k as usize].modpow(q_rem, n);
            pi = (pi * pi_rem) % n;
        }

        // Package y and pi into the VdfProof.
        // Both y and pi are computed mod N (2048-bit), so their byte representations
        // are guaranteed to be <= 256 bytes. We guard defensively to prevent a
        // usize underflow panic if the BigUint arithmetic ever violates this invariant.
        let y_bytes = y.to_bytes_be();
        let pi_bytes = pi.to_bytes_be();

        if y_bytes.len() > 256 || pi_bytes.len() > 256 {
            return Err(VdfError::ProofGenerationError);
        }

        let mut proof_bytes = vec![0u8; 512];
        let y_start = 256 - y_bytes.len();
        proof_bytes[y_start..256].copy_from_slice(&y_bytes);

        let pi_start = 512 - pi_bytes.len();
        proof_bytes[pi_start..512].copy_from_slice(&pi_bytes);

        Ok(VdfProof { proof_bytes })
    }

    fn verify(
        &self,
        challenge: &Commitment,
        proof: &VdfProof,
        iterations: u64,
    ) -> Result<bool, VdfError> {
        if proof.proof_bytes.len() != 512 {
            return Err(VdfError::InvalidProof);
        }

        // A proof for zero iterations is semantically nonsensical.
        // Reject early rather than silently evaluating a degenerate case.
        if iterations == 0 {
            return Err(VdfError::InvalidProof);
        }

        let x = BigUint::from_bytes_be(&challenge.hash);
        let n = &self.n;

        let y = BigUint::from_bytes_be(&proof.proof_bytes[0..256]);
        let pi = BigUint::from_bytes_be(&proof.proof_bytes[256..512]);

        let l = hash_to_prime::generate_prime_l(&x, &y);

        // Compute r = 2^T mod l using modpow to avoid allocating a ~37GB BigUint
        // for production-scale iteration counts. 2^T mod l is identical to:
        //   base=2, exp=iterations, modulus=l
        let two = BigUint::from(2u64);
        let t = BigUint::from(iterations);
        let r = two.modpow(&t, &l);

        let pi_l = pi.modpow(&l, n);
        let x_r = x.modpow(&r, n);
        let lhs = (pi_l * x_r) % n;

        Ok(lhs == y)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn test_blockwise_prover_and_verifier() {
        let engine = RsaVdfEngine::new();

        let hash = kinetic_primitives::sha256_hash(b"kinetic-blockwise-test");
        let challenge = Commitment { hash };

        let iterations = 10_000;

        println!(
            "Starting Blockwise Wesolowski Prover ({} iterations)...",
            iterations
        );
        let start = Instant::now();
        let proof = engine.evaluate(&challenge, iterations).unwrap();
        let prover_time = start.elapsed();
        println!("Blockwise Prover finished in {:?}", prover_time);

        println!("Starting Wesolowski Verifier...");
        let start = Instant::now();
        let is_valid = engine.verify(&challenge, &proof, iterations).unwrap();
        let verifier_time = start.elapsed();
        println!("Verifier finished in {:?}", verifier_time);

        assert!(is_valid, "Blockwise Wesolowski proof failed verification!");
    }

    #[test]
    fn test_odd_iterations() {
        let engine = RsaVdfEngine::new();
        let challenge = Commitment { hash: [1u8; 32] };
        let iterations = 10_005;

        let proof = engine.evaluate(&challenge, iterations).unwrap();
        let is_valid = engine.verify(&challenge, &proof, iterations).unwrap();

        assert!(
            is_valid,
            "Proof failed for iterations not divisible by block size!"
        );
    }

    // --- SECURITY: Tampered proof must be rejected ---
    #[test]
    fn test_tampered_pi_is_rejected() {
        let engine = RsaVdfEngine::new();
        let challenge = Commitment { hash: [2u8; 32] };
        let iterations = 5_000;

        let mut proof = engine.evaluate(&challenge, iterations).unwrap();

        // Flip a single byte inside the pi region (bytes 256..512)
        proof.proof_bytes[300] ^= 0xFF;

        let is_valid = engine.verify(&challenge, &proof, iterations).unwrap();
        assert!(
            !is_valid,
            "SECURITY FLAW: A tampered proof (corrupted pi) was accepted as valid!"
        );
    }

    // --- SECURITY: Tampered output (y) must be rejected ---
    #[test]
    fn test_tampered_y_is_rejected() {
        let engine = RsaVdfEngine::new();
        let challenge = Commitment { hash: [3u8; 32] };
        let iterations = 5_000;

        let mut proof = engine.evaluate(&challenge, iterations).unwrap();

        // Flip a single byte inside the y region (bytes 0..256)
        proof.proof_bytes[10] ^= 0xFF;

        let is_valid = engine.verify(&challenge, &proof, iterations).unwrap();
        assert!(
            !is_valid,
            "SECURITY FLAW: A tampered proof (corrupted y) was accepted as valid!"
        );
    }

    // --- SECURITY: Verifying with wrong iteration count must be rejected ---
    #[test]
    fn test_wrong_iterations_is_rejected() {
        let engine = RsaVdfEngine::new();
        let challenge = Commitment { hash: [4u8; 32] };
        let real_iterations = 5_000;

        let proof = engine.evaluate(&challenge, real_iterations).unwrap();

        // Claim a different iteration count to the verifier
        let is_valid = engine
            .verify(&challenge, &proof, real_iterations + 1)
            .unwrap();
        assert!(
            !is_valid,
            "SECURITY FLAW: Verifier accepted a proof with a mismatched iteration count!"
        );
    }

    // --- SECURITY: Truncated proof must return Err, not panic ---
    #[test]
    fn test_truncated_proof_returns_error() {
        let engine = RsaVdfEngine::new();
        let challenge = Commitment { hash: [5u8; 32] };

        let bad_proof = VdfProof {
            proof_bytes: vec![0u8; 256], // only half the required 512 bytes
        };

        let result = engine.verify(&challenge, &bad_proof, 1_000);
        assert!(
            matches!(result, Err(VdfError::InvalidProof)),
            "SECURITY FLAW: Verifier did not return InvalidProof for a truncated proof!"
        );
    }

    // --- SECURITY: Empty proof must return Err, not panic ---
    #[test]
    fn test_empty_proof_returns_error() {
        let engine = RsaVdfEngine::new();
        let challenge = Commitment { hash: [6u8; 32] };

        let bad_proof = VdfProof {
            proof_bytes: vec![],
        };

        let result = engine.verify(&challenge, &bad_proof, 1_000);
        assert!(
            matches!(result, Err(VdfError::InvalidProof)),
            "SECURITY FLAW: Verifier did not return InvalidProof for an empty proof!"
        );
    }

    // --- SOUNDNESS: Different challenges produce different outputs ---
    #[test]
    fn test_different_challenges_produce_different_outputs() {
        let engine = RsaVdfEngine::new();
        let iterations = 3_000;

        let challenge_a = Commitment { hash: [0xAAu8; 32] };
        let challenge_b = Commitment { hash: [0xBBu8; 32] };

        let proof_a = engine.evaluate(&challenge_a, iterations).unwrap();
        let proof_b = engine.evaluate(&challenge_b, iterations).unwrap();

        // The y values (first 256 bytes) must differ
        assert_ne!(
            &proof_a.proof_bytes[0..256],
            &proof_b.proof_bytes[0..256],
            "SOUNDNESS FLAW: Two different challenges produced identical VDF outputs!"
        );
    }

    // --- SOUNDNESS: Cross-challenge verification must be rejected ---
    #[test]
    fn test_cross_challenge_proof_is_rejected() {
        let engine = RsaVdfEngine::new();
        let iterations = 3_000;

        let challenge_a = Commitment { hash: [0xCCu8; 32] };
        let challenge_b = Commitment { hash: [0xDDu8; 32] };

        // Generate a valid proof for challenge_a
        let proof_a = engine.evaluate(&challenge_a, iterations).unwrap();

        // Try to pass it off as a proof for challenge_b
        let is_valid = engine.verify(&challenge_b, &proof_a, iterations).unwrap();
        assert!(
            !is_valid,
            "SECURITY FLAW: A proof for challenge_a was accepted as valid for challenge_b!"
        );
    }

    // --- EDGE CASE: Single iteration ---
    #[test]
    fn test_single_iteration() {
        let engine = RsaVdfEngine::new();
        let challenge = Commitment { hash: [7u8; 32] };

        let proof = engine.evaluate(&challenge, 1).unwrap();
        let is_valid = engine.verify(&challenge, &proof, 1).unwrap();

        assert!(is_valid, "Proof failed for a single iteration!");
    }

    // --- CONSENSUS: Same inputs must always produce bit-identical proof bytes ---
    // If the Prover is non-deterministic, two nodes will split on which proof is canonical.
    #[test]
    fn test_prover_is_deterministic() {
        let engine = RsaVdfEngine::new();
        let challenge = Commitment { hash: [8u8; 32] };
        let iterations = 8_000;

        let proof_a = engine.evaluate(&challenge, iterations).unwrap();
        let proof_b = engine.evaluate(&challenge, iterations).unwrap();

        assert_eq!(
            proof_a.proof_bytes, proof_b.proof_bytes,
            "CONSENSUS FLAW: Prover produced different proof bytes for identical inputs! Network will split."
        );
    }

    // --- EDGE CASE: All-zero challenge must be explicitly rejected ---
    // x=0 is a degenerate input where y stays 0 for all squarings, producing a
    // zero proof that verifies trivially against any challenge. The engine must
    // reject this at the evaluate() boundary with VdfError::InvalidChallenge.
    #[test]
    fn test_all_zero_challenge_is_rejected() {
        let engine = RsaVdfEngine::new();
        let zero_challenge = Commitment { hash: [0u8; 32] };

        let result = engine.evaluate(&zero_challenge, 1_000);
        assert!(
            matches!(result, Err(VdfError::InvalidChallenge)),
            "SECURITY FLAW: Degenerate zero challenge was not rejected! Got: {:?}",
            result
        );
    }

    // --- STRESS: Large iteration count to validate blockwise checkpoint math at scale ---
    #[test]
    fn test_large_iteration_count() {
        let engine = RsaVdfEngine::new();
        let challenge = Commitment { hash: [9u8; 32] };
        let iterations = 50_000;

        let proof = engine.evaluate(&challenge, iterations).unwrap();
        let is_valid = engine.verify(&challenge, &proof, iterations).unwrap();

        assert!(
            is_valid,
            "MATH FLAW: Blockwise checkpointing failed at large scale ({} iterations)!",
            iterations
        );
    }

    // --- ERROR GUARD: evaluate() with zero iterations must return InvalidChallenge ---
    #[test]
    fn test_zero_iterations_evaluate_is_rejected() {
        let engine = RsaVdfEngine::new();
        let challenge = Commitment { hash: [0xABu8; 32] };

        let result = engine.evaluate(&challenge, 0);
        assert!(
            matches!(result, Err(VdfError::InvalidChallenge)),
            "SECURITY FLAW: evaluate(iterations=0) did not return InvalidChallenge! Got: {:?}",
            result
        );
    }

    // --- ERROR GUARD: verify() with zero iterations must return InvalidProof ---
    #[test]
    fn test_zero_iterations_verify_is_rejected() {
        let engine = RsaVdfEngine::new();
        let challenge = Commitment { hash: [0xCDu8; 32] };

        // Build a structurally valid 512-byte proof filled with arbitrary bytes
        let fake_proof = VdfProof {
            proof_bytes: vec![0x42u8; 512],
        };

        let result = engine.verify(&challenge, &fake_proof, 0);
        assert!(
            matches!(result, Err(VdfError::InvalidProof)),
            "SECURITY FLAW: verify(iterations=0) did not return InvalidProof! Got: {:?}",
            result
        );
    }
}
