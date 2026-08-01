fn main() {
    let json = serde_json::json!({
        "protocol_version": 1,
        "name": "test.kin",
        "payload": [],
        "salt": vec![0; 32],
        "drand_pulse": 0,
        "drand_randomness": "0".repeat(64),
        "iterations": 1,
        "vdf_proof": { "proof_bytes": [] },
        "pubkey": [],
        "signature": []
    });
    let record: Result<kinetic_core::types::DomainRecord, _> = serde_json::from_value(json);
    println!("{:?}", record);
}
