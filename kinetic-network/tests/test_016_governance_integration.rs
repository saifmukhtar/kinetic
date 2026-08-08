use kinetic_core::governance::GLOBAL_GOVERNANCE_STATE;
use kinetic_core::types::NameRecord;

use kinetic_network::store::core::KineticRecordStore;
use libp2p::identity;
use libp2p::kad::store::RecordStore;
use libp2p::kad::Record;
use tempfile::tempdir;

#[tokio::test]
async fn test_016_governance_integration_halt() {
    let dir = tempdir().unwrap();
    let storage_path = dir.path().join("kinetic_db");
    let storage = std::sync::Arc::new(
        kinetic_storage::SledStorage::new(storage_path.to_str().unwrap()).unwrap(),
    );

    let local_key = identity::Keypair::generate_ed25519();
    let local_peer_id = libp2p::PeerId::from_public_key(&local_key.public());

    let vdf_engine = std::sync::Arc::new(kinetic_vdf::ChiaVdfEngine::new());

    let mut store = KineticRecordStore::new(
        local_peer_id,
        storage,
        1000,
        std::num::NonZeroUsize::new(100).unwrap(),
        100,
        vdf_engine,
    );

    // Halt the network globally
    {
        let mut state = GLOBAL_GOVERNANCE_STATE.lock().unwrap();
        state.is_halted = true;
    }

    // Try to inject a fake reveal
    let fake_reveal = kinetic_core::types::Reveal {
        name: "test".to_string(),
        pubkey: vec![1; 32],
        salt: [0; 32],
        drand_signature: "0000".to_string(), // invalid but will be rejected by halt first
        drand_kyn: 1000,
        iterations: 1000,
        vdf_proof: kinetic_core::types::VdfProof {
            proof_bytes: vec![],
        },
        previous_proof: None,
        signature: vec![],
        miner_pubkey: None,
        payload: vec![],
        protocol_version: 2,
        authorization: None,
    };

    let domain_record = NameRecord::Standard(Box::new(fake_reveal));
    let record_bytes = serde_json::to_vec(&domain_record).unwrap();
    let record = Record::new(libp2p::kad::RecordKey::new(&"test"), record_bytes);

    let res = store.put(record);
    assert!(res.is_err());

    // Unhalt
    {
        let mut state = GLOBAL_GOVERNANCE_STATE.lock().unwrap();
        state.is_halted = false;
    }
}

#[tokio::test]
async fn test_016_governance_integration_premium() {
    let dir = tempdir().unwrap();
    let storage_path = dir.path().join("kinetic_db");
    let storage = std::sync::Arc::new(
        kinetic_storage::SledStorage::new(storage_path.to_str().unwrap()).unwrap(),
    );

    let local_key = identity::Keypair::generate_ed25519();
    let local_peer_id = libp2p::PeerId::from_public_key(&local_key.public());

    let vdf_engine = std::sync::Arc::new(kinetic_vdf::ChiaVdfEngine::new());

    // Set current drand kyn to 10 years in the future
    let future_round = 10_000_000;

    let mut store = KineticRecordStore::new(
        local_peer_id,
        storage,
        future_round,
        std::num::NonZeroUsize::new(100).unwrap(),
        100,
        vdf_engine,
    );

    // Create a premium record
    let domain_record = NameRecord::Premium {
        name: "test_premium".to_string(),
        pubkey: vec![1; 32],
        granted_at: 0,
        payload: vec![],
        signature: vec![],
        authorization: None,
    };

    let record_bytes = serde_json::to_vec(&domain_record).unwrap();
    let record = Record::new(libp2p::kad::RecordKey::new(&"test_premium"), record_bytes);

    let res = store.put(record);
    assert!(res.is_ok());
}
