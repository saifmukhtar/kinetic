use num_bigint::BigUint;
use num_prime::nt_funcs::is_prime;
use sha2::{Digest, Sha256};

/// Generates a deterministic prime `l` (used as the quotient divisor in Wesolowski proofs)
/// by hashing the VDF challenge (`x`) and the VDF output (`y`) using the Fiat-Shamir heuristic.
///
/// The resulting prime is guaranteed to be exactly 256 bits long.
pub fn generate_prime_l(x: &BigUint, y: &BigUint) -> BigUint {
    let x_bytes = x.to_bytes_be();
    let y_bytes = y.to_bytes_be();

    let mut counter = 0u64;

    loop {
        let mut hasher = Sha256::new();
        hasher.update(&x_bytes);
        hasher.update(&y_bytes);
        hasher.update(&counter.to_be_bytes());

        let hash_result = hasher.finalize();
        let mut candidate_bytes = hash_result.to_vec();

        // Force the lowest bit to 1 (must be odd to be prime)
        candidate_bytes[31] |= 1;

        // Force the highest bit to 1 (must be exactly 256 bits long)
        candidate_bytes[0] |= 0x80;

        let candidate = BigUint::from_bytes_be(&candidate_bytes);

        // Run Miller-Rabin primality test.
        // The default config provides negligible error probability.
        if is_prime(&candidate, None).probably() {
            return candidate;
        }

        counter += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deterministic_hash_to_prime() {
        let x = BigUint::from(12345u64);
        let y = BigUint::from(67890u64);

        // The generator should be perfectly deterministic
        let prime1 = generate_prime_l(&x, &y);
        let prime2 = generate_prime_l(&x, &y);

        assert_eq!(prime1, prime2, "Prime generation is not deterministic!");

        // Verify it's actually prime
        assert!(
            is_prime(&prime1, None).probably(),
            "Generated number is not prime!"
        );

        // Verify it is exactly 256 bits
        assert_eq!(prime1.bits(), 256, "Prime is not 256 bits!");

        // Ensure changing the inputs changes the prime
        let y_different = BigUint::from(67891u64);
        let prime3 = generate_prime_l(&x, &y_different);
        assert_ne!(prime1, prime3, "Different inputs generated the same prime!");

        println!("Generated 256-bit prime: {}", prime1);
    }
}
