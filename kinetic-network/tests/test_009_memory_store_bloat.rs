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

    let vdf_engine: std::sync::Arc<dyn kinetic_core::traits::VdfEngine> =
        std::sync::Arc::new(kinetic_vdf::ChiaVdfEngine::new());
    let mut store = KineticRecordStore::new(
        peer_id,
        storage,
        0,
        std::num::NonZeroUsize::new(100).unwrap(),
        100,
        vdf_engine,
    );

    // Insert 15,000 reveals.
    for i in 0..15_000 {
        let name = format!("name{}.kin", i);
        store.reveals_by_name.put(
            name.clone(),
            kinetic_core::types::NameRecord::Standard(Box::new(Reveal {
                name,
                salt: [0; 32],
                drand_signature: String::new(),
                drand_kyn: 100,
                iterations: 100,
                vdf_proof: kinetic_core::types::VdfProof {
                    proof_bytes: vec![],
                },
                signature: vec![],
                protocol_version: 1,
                pubkey: vec![],
                payload: vec![],
                previous_proof: None,
                miner_pubkey: None,
                authorization: None,
            })),
        );
    }

    // Check if unbounded bloat occurred
    assert!(
        store.reveals_by_name.len() <= 10_000,
        "SECURITY FLAW: Memory store bloat! 15,000 records were stored in memory unconditionally. Currently holding {} records.",
        store.reveals_by_name.len()
    );
}
