fn main() {
    let root_bytes =
        hex::decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").unwrap();
    let root_sk = ed25519_dalek::SigningKey::from_bytes(root_bytes.as_slice().try_into().unwrap());
    let root_pk = root_sk.verifying_key().to_bytes();
    println!("ROOT_PK={}", hex::encode(root_pk));

    let guard_bytes =
        hex::decode("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef").unwrap();
    let guard_sk =
        ed25519_dalek::SigningKey::from_bytes(guard_bytes.as_slice().try_into().unwrap());
    let guard_pk = guard_sk.verifying_key().to_bytes();
    println!("GUARD_PK={}", hex::encode(guard_pk));
}
