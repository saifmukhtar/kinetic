use ed25519_dalek::SigningKey;
use std::fs;

fn main() {
    let secret = fs::read("/home/saif/.config/kinetic/identity.kin").unwrap();
    let signing_key = SigningKey::try_from(secret.as_slice()).unwrap();
    let pubkey = signing_key.verifying_key().to_bytes();
    println!("{:?}", pubkey);
}
