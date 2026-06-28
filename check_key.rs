use std::fs;
use ed25519_dalek::SigningKey;

fn main() {
    let bytes = fs::read("/home/saif/Documents/genesis_identity.kin").unwrap();
    let mut array = [0u8; 32];
    array.copy_from_slice(&bytes);
    let key = SigningKey::from_bytes(&array);
    let pubkey = key.verifying_key().to_bytes();
    println!("{:?}", pubkey);
}
