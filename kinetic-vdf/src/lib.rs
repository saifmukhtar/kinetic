use kinetic_core::traits::VdfEngine;
use kinetic_core::types::{Commitment, VdfProof};
use kinetic_core::KineticError;

/// A Rust wrapper around the external `chiavdf` library.
pub struct ChiaVdfEngine;

impl ChiaVdfEngine {
    pub fn new() -> Self {
        Self
    }

    // Helper to generate the default class group element
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
    fn evaluate(&self, challenge: &Commitment, iterations: u64) -> Result<VdfProof, KineticError> {
        // Acquire system-wide lock to prevent concurrent VDF CPU starvation
        use fs2::FileExt;
        let lock_path = std::env::temp_dir().join("kinetic_vdf.lock");
        let lock_file = std::fs::File::create(&lock_path).map_err(|e| {
            KineticError::Internal(format!("Failed to create VDF lock file: {}", e))
        })?;

        lock_file
            .lock_exclusive()
            .map_err(|e| KineticError::Internal(format!("Failed to acquire VDF lock: {}", e)))?;

        // Chia VDF requires a 1024-bit discriminant (128 bytes) generated from the challenge seed.
        // We use the 32-byte hash as the seed.
        let mut disc = [0u8; 128];
        if !chiavdf::create_discriminant(&challenge.hash, &mut disc) {
            return Err(KineticError::Internal(
                "Failed to create VDF discriminant".to_string(),
            ));
        }

        let default_el = Self::default_element();

        let result = match chiavdf::prove(&challenge.hash, &default_el, 1024, iterations) {
            Some(proof_bytes) => Ok(VdfProof { proof_bytes }),
            None => Err(KineticError::Internal(
                "Failed to generate VDF proof".to_string(),
            )),
        };

        // Lock file is dropped and released automatically here
        result
    }

    fn verify(
        &self,
        challenge: &Commitment,
        proof: &VdfProof,
        iterations: u64,
    ) -> Result<bool, KineticError> {
        let mut disc = [0u8; 128];
        if !chiavdf::create_discriminant(&challenge.hash, &mut disc) {
            return Err(KineticError::Internal(
                "Failed to create VDF discriminant".to_string(),
            ));
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
    fn evaluate(
        &self,
        _challenge: &Commitment,
        _iterations: u64,
    ) -> Result<VdfProof, KineticError> {
        Err(kinetic_core::error::KineticError::Internal(
            "VDF evaluation is unsupported on Android".to_string(),
        ))
    }

    fn verify(
        &self,
        _challenge: &Commitment,
        _proof: &VdfProof,
        _iterations: u64,
    ) -> Result<bool, KineticError> {
        Err(kinetic_core::error::KineticError::Internal(
            "VDF verification is unsupported on Android".to_string(),
        ))
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
        // Small number of iterations so the test is fast, but it tests real chiavdf logic
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
