use ml_dsa::{MlDsa65, KeyExport};
use ml_dsa::signature::Keypair;

fn main() {
    let bytes1 = hex::decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").unwrap();
    let sk1 = ml_dsa::SigningKey::<MlDsa65>::from_seed(bytes1.as_slice().try_into().unwrap());
    let pk1 = sk1.verifying_key().to_bytes();
    println!("ROOT_PUBLIC_KEY_HEX:\n{}", hex::encode(pk1));
    
    let bytes2 = hex::decode("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef").unwrap();
    let sk2 = ml_dsa::SigningKey::<MlDsa65>::from_seed(bytes2.as_slice().try_into().unwrap());
    let pk2 = sk2.verifying_key().to_bytes();
    println!("GUARD_PUBLIC_KEY_HEX:\n{}", hex::encode(pk2));
}
