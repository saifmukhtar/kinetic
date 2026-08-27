use ml_dsa::{Generate, MlDsa65, SigningKey, KeyInit, Keypair};
use ml_dsa::signature::Signer;

/// A unified wrapper around the ML-DSA-65 post-quantum signing key.
/// Centralizing this here allows us to banish the `ml-dsa` dependency
/// from all other crates in the workspace.
#[derive(Clone)]
pub struct KineticKeypair(SigningKey<MlDsa65>);

impl KineticKeypair {
    /// Generates a completely new, cryptographically random keypair.
    pub fn generate() -> Self {
        Self(SigningKey::<MlDsa65>::generate())
    }

    /// Derives a keypair deterministically from a 32-byte seed.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self(SigningKey::<MlDsa65>::from_seed(seed.into()))
    }

    /// Reconstructs a keypair from its full serialized bytes.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, &'static str> {
        SigningKey::<MlDsa65>::new_from_slice(bytes)
            .map(Self)
            .map_err(|_| "Failed to decode ML-DSA-65 private key")
    }

    /// Signs a message and returns the raw signature bytes.
    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        let sig = self.0.sign(msg);
        use ml_dsa::SignatureEncoding;
        sig.to_bytes().to_vec()
    }

    /// Returns the public key as raw bytes.
    pub fn pubkey_bytes(&self) -> Vec<u8> {
        use ml_dsa::KeyExport;
        self.0.verifying_key().to_bytes().to_vec()
    }

    /// Exports the private key to a byte vector.
    pub fn to_bytes(&self) -> Vec<u8> {
        use ml_dsa::KeyExport;
        self.0.to_bytes().to_vec()
    }
}
