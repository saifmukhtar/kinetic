use kinetic_core::types::vdf::{PreviousProof, Reveal, VdfProof};
use kinetic_network::store::core::KineticRecordStore;
use kinetic_storage::KineticStorage;
use libp2p::{PeerId, kad};
use proptest::prelude::*;
use std::num::NonZeroUsize;
use std::sync::Arc;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    #[test]
    fn test_store_garbage_payloads(
        garbage in any::<Vec<u8>>()
    ) {
        let temp_dir = tempfile::tempdir().unwrap();
        let sled_storage = Arc::new(KineticStorage::new(temp_dir.path()).unwrap());
        let keypair = libp2p::identity::ed25519::Keypair::generate();
        let public = keypair.public();
        let identity = libp2p::identity::PublicKey::from(public);
        let peer_id = PeerId::from(identity);

        let vdf_engine: Arc<dyn kinetic_core::traits::VdfEngine> = Arc::new(kinetic_vdf_rsa::RsaVdfEngine::new());
        let mut store = KineticRecordStore::new(
            peer_id,
            sled_storage,
            0,
            NonZeroUsize::new(100).unwrap(),
            100,
            vdf_engine,
        );

        let key = kad::RecordKey::new(&[0u8; 32]);
        let record = kad::Record::new(key, garbage);

        // Put record might fail because it's garbage, but it MUST NOT panic.
        let _ = store.put(record);
    }

    #[test]
    fn test_required_iterations_panic_safety(
        name in "[a-z0-9-]{1,63}\\.kin",
        kyn in any::<u64>(),
        prev_pulse in any::<u64>(),
        prev_iterations in any::<u64>()
    ) {
        let reveal = Reveal {
            protocol_version: 1,
            name: name.clone(),
            payload: vec![],
            salt: [0u8; 32],
            kyn,
            drand_signature: "abcd".to_string(),
            iterations: 1000,
            vdf_proof: VdfProof { proof_bytes: vec![] },
            pubkey: vec![0u8; 32],
            signature: vec![0u8; 64],
            previous_proof: Some(PreviousProof {
                salt: [0u8; 32],
                kyn: prev_pulse,
                drand_signature: "abcd".to_string(),
                iterations: prev_iterations,
                vdf_proof: VdfProof { proof_bytes: vec![] },
                signature: vec![0u8; 64],
            }),
            miner_pubkey: None,
            authorization: None,
        };

        let temp_dir = tempfile::tempdir().unwrap();
        let sled_storage = Arc::new(KineticStorage::new(temp_dir.path()).unwrap());
        let keypair = libp2p::identity::ed25519::Keypair::generate();
        let public = keypair.public();
        let identity = libp2p::identity::PublicKey::from(public);
        let peer_id = PeerId::from(identity);

        let vdf_engine: Arc<dyn kinetic_core::traits::VdfEngine> = Arc::new(kinetic_vdf_rsa::RsaVdfEngine::new());
        let mut store = KineticRecordStore::new(
            peer_id,
            sled_storage,
            0,
            NonZeroUsize::new(100).unwrap(),
            100,
            vdf_engine,
        );
        store.current_kyn = kyn.saturating_add(100);

        let payload = serde_json::to_vec(&reveal).unwrap();
        let key = kad::RecordKey::new(&[0u8; 32]);
        let record = kad::Record::new(key, payload);

        // We expect an error (e.g., InvalidSignature, InvalidVdf),
        // but it should successfully compute iteration boundaries without underflowing.
        let _ = store.put(record);
    }
}
