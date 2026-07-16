use ed25519_dalek::SigningKey;
use std::fs;

fn main() {
    let mut key_path = dirs::config_dir().expect("Could not find config directory");
    key_path.push("kinetic/identity.key");
    let secret = fs::read(&key_path).expect("Failed to read identity.key");
    let signing_key = SigningKey::try_from(secret.as_slice()).unwrap();
    let pubkey = signing_key.verifying_key().to_bytes();
    println!("{:?}", pubkey);
}
