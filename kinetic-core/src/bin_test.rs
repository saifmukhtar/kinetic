use ed25519_dalek::SigningKey;
use std::fs;

fn main() {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "genesis_identity.kin".to_string());
    let bytes = fs::read(&path).unwrap_or_else(|e| panic!("Failed to read {}: {}", path, e));
    let mut array = [0u8; 32];
    array.copy_from_slice(&bytes);
    let key = SigningKey::from_bytes(&array);
    let pubkey = key.verifying_key().to_bytes();
    println!("{:?}", pubkey);
}
