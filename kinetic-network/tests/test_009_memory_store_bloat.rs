use kinetic_core::types::Reveal;
use kinetic_network::store::KineticRecordStore;
use kinetic_storage::SledStorage;
use libp2p::identity::Keypair;
use libp2p::PeerId;
use std::sync::Arc;
use tempfile::tempdir;

#[test]
fn test_009_memory_store_bloat() {
    let dir = tempdir().unwrap();
    let storage = Arc::new(SledStorage::new(dir.path()).unwrap());
    let peer_id = PeerId::from(Keypair::generate_ed25519().public());

    let mut store = KineticRecordStore::new(peer_id, storage, 0);

    // Insert 15,000 reveals.
    for i in 0..15_000 {
        let name = format!("name{}.kin", i);
        store.reveals_by_name.put(
            name.clone(),
            Reveal {
                name,
                salt: [0; 32],
                drand_randomness: String::new(),
                drand_pulse: 0,
                iterations: 0,
                vdf_proof: kinetic_core::types::VdfProof {
                    proof_bytes: vec![],
                },
                pubkey: vec![],
                signature: vec![],
                protocol_version: 2,
                payload: vec![],
            },
        );
    }

    // Check if unbounded bloat occurred
    assert!(
        store.reveals_by_name.len() <= 10_000,
        "SECURITY FLAW: Memory store bloat! 15,000 records were stored in memory unconditionally. Currently holding {} records.",
        store.reveals_by_name.len()
    );
}
