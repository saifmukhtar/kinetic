use ml_dsa::signature::Signer;
use ml_dsa::{Generate, KeyInit, Keypair, MlDsa65, SigningKey};

/// A unified wrapper around the ML-DSA-65 post-quantum signing key.
///
/// Centralizing this here allows us to banish the `ml-dsa` dependency from all other 
/// crates in the workspace, ensuring the broader Kinetic network never interacts with 
/// raw cryptographic libraries directly.
///
/// # Security
/// This struct holds highly sensitive post-quantum private key material in memory. 
/// It must never be serialized indiscriminately or logged. 
///
/// # Examples
/// ```rust
/// use kinetic_primitives::core::KineticKeypair;
/// 
/// // Generate a fresh post-quantum keypair
/// let keypair = KineticKeypair::generate();
/// 
/// // Sign a message
/// let message = b"kinetic network consensus payload";
/// let signature = keypair.sign(message);
/// 
/// // The public key can be safely exported for verification
/// let pubkey = keypair.to_public_bytes();
/// assert!(!pubkey.is_empty());
/// ```
#[derive(Clone)]
pub struct KineticKeypair(SigningKey<MlDsa65>);

impl KineticKeypair {
    /// Generates a completely new, cryptographically random keypair.
    ///
    /// # Security
    /// This relies on the operating system's underlying CSPRNG (Cryptographically Secure 
    /// Pseudorandom Number Generator) to ensure sufficient entropy.
    pub fn generate() -> Self {
        Self(SigningKey::<MlDsa65>::generate())
    }

    /// Derives a keypair deterministically from a 32-byte seed.
    ///
    /// This is strictly used for recovering identities from a master seed phrase or 
    /// performing deterministic key derivation.
    ///
    /// # Security
    /// The caller is entirely responsible for ensuring the provided `seed` contains 
    /// 256 bits of true cryptographic entropy.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self(SigningKey::<MlDsa65>::from_seed(seed.into()))
    }

    /// Reconstructs a keypair from its full serialized bytes.
    ///
    /// # Errors
    /// Returns an error if the provided byte slice is not the exact required length 
    /// for an ML-DSA-65 private key, or if the bytes are mathematically malformed.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, &'static str> {
        SigningKey::<MlDsa65>::new_from_slice(bytes)
            .map(Self)
            .map_err(|_| "Failed to decode ML-DSA-65 private key")
    }

    /// Cryptographically signs a message and returns the raw signature bytes.
    ///
    /// # Network / Blocking
    /// Note that ML-DSA-65 signatures are significantly larger than classical ECDSA 
    /// signatures (often exceeding 3KB). Callers should be mindful of network payload 
    /// limits when broadcasting these signatures.
    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        let sig = self.0.sign(msg);
        use ml_dsa::SignatureEncoding;
        sig.to_bytes().to_vec()
    }

    /// Exports the public key component as raw bytes.
    ///
    /// # Security
    /// Public keys are safe to share across the Kinetic network and are typically 
    /// embedded inside a Kinetic Identity Document (KID).
    pub fn to_public_bytes(&self) -> Vec<u8> {
        use ml_dsa::KeyExport;
        self.0.verifying_key().to_bytes().to_vec()
    }

    /// Exports the highly sensitive private key to a raw byte vector.
    ///
    /// # Security
    /// **CRITICAL**: This exports raw, unencrypted private key material. The caller 
    /// is strictly responsible for immediately encrypting or securely wiping this 
    /// byte vector after writing it to storage.
    pub fn to_secret_bytes(&self) -> Vec<u8> {
        use ml_dsa::KeyExport;
        self.0.to_bytes().to_vec()
    }
}

