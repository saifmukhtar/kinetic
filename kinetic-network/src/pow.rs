use sha2::{Sha256, Digest};

/// Hashcash implementation to prevent connection spam and DoS attacks.
/// Before a peer is allowed to open a Yamux stream to gossip `.kin` records,
/// they must solve a Hashcash puzzle.
pub struct Hashcash {
    pub difficulty: u32,
}

impl Hashcash {
    pub fn new(difficulty: u32) -> Self {
        Self { difficulty }
    }

    /// Verifies if H(data || nonce) has at least `difficulty` leading zero bits.
    pub fn verify(&self, data: &[u8], nonce: u64) -> bool {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.update(nonce.to_be_bytes());
        let result = hasher.finalize();

        // Count leading zeros
        let mut zero_bits = 0;
        for byte in result {
            if byte == 0 {
                zero_bits += 8;
            } else {
                zero_bits += byte.leading_zeros();
                break;
            }
        }

        zero_bits >= self.difficulty
    }
}
