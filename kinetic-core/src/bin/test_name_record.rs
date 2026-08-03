fn main() {
    let json = serde_json::json!({
        "protocol_version": 1,
        "name": "test.kin",
        "payload": [],
        "salt": vec![0; 32],
        "drand_kyn": 0,
        "drand_signature": "0".repeat(192),
        "iterations": 1,
        "vdf_proof": { "proof_bytes": [] },
        "pubkey": [],
        "signature": []
    });
    let record: Result<kinetic_core::types::NameRecord, _> = serde_json::from_value(json);
    println!("{:?}", record);
}
