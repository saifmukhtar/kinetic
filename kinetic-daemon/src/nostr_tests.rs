#[cfg(test)]
mod tests {
    use crate::nostr::verify_hashcash;

    #[test]
    fn test_hashcash_proof_of_work_verification() {
        let challenge = [1u8; 32];

        // Find a valid nonce (takes some compute, so let's precompute or search briefly)
        let mut valid_nonce = 0;
        loop {
            if verify_hashcash(&challenge, valid_nonce) {
                break;
            }
            valid_nonce += 1;
        }

        // Must be true for the valid nonce
        assert!(verify_hashcash(&challenge, valid_nonce));

        // Must be false for an invalid nonce
        assert!(!verify_hashcash(&challenge, valid_nonce.wrapping_add(1)));
    }
}
