//! Auxiliary binary utility for computing static ML-DSA-65 council public keys from seeds.

use ml_dsa::{KeyExport, MlDsa65};

fn main() {
    let bytes1 = hex::decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").unwrap();
    let sk1 = ml_dsa::SigningKey::<MlDsa65>::from_seed(bytes1.as_slice().try_into().unwrap());
    let pk1 = sk1.verifying_key().to_bytes();
    println!("ROOT_PUBLIC_KEY_HEX:\n{}", hex::encode(pk1));
    
}
