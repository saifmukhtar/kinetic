//! Helper CLI utility extracting public key bytes from the Kinetic host identity file.

use ed25519_dalek::SigningKey;
use std::fs;

fn main() {
    let key_path = kinetic_core::config::get_base_dir().join("identity.key");
    let secret = fs::read(&key_path).expect("Failed to read identity.key");
    let signing_key = SigningKey::try_from(secret.as_slice()).unwrap();
    let pubkey = signing_key.verifying_key().to_bytes();
    println!("{:?}", pubkey);
}
