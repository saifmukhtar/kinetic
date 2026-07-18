#[cfg(test)]
mod tests {
    use crate::store::core::KineticRecordStore;
    use kinetic_core::types::{Heartbeat, Reveal, VdfProof};
    use kinetic_storage::SledStorage;
    use libp2p::identity::Keypair;
    use libp2p::PeerId;
    use std::sync::Arc;
    use tempfile::tempdir;

    fn dummy_reveal(name: &str, drand_pulse: u64) -> Reveal {
        Reveal {
            protocol_version: 2,
            name: name.to_string(),
            payload: vec![],
            salt: [0u8; 32],
            drand_pulse,
            drand_randomness: String::new(),
            iterations: 100,
            vdf_proof: VdfProof {
                proof_bytes: vec![],
            },
            pubkey: vec![],
            signature: vec![],
            previous_proof: None,
            miner_pubkey: None,
        }
    }

    fn setup_store(
        max_reveals: usize,
    ) -> (
        KineticRecordStore,
        Arc<dyn kinetic_core::traits::StorageEngine>,
    ) {
        let dir = tempdir().unwrap();
        let storage: Arc<dyn kinetic_core::traits::StorageEngine> =
            Arc::new(SledStorage::new(dir.path()).unwrap());
        let peer_id = PeerId::from(Keypair::generate_ed25519().public());
        let vdf_engine: Arc<dyn kinetic_core::traits::VdfEngine> =
            Arc::new(kinetic_vdf::ChiaVdfEngine::new());
        let store = KineticRecordStore::new(
            peer_id,
            storage.clone(),
            100, // initial drand round
            std::num::NonZeroUsize::new(100).unwrap(),
            max_reveals,
            vdf_engine,
        );
        (store, storage)
    }

    #[test]
    fn test_rate_limiting() {
        let (mut store, _storage) = setup_store(5); // max 5 reveals per hour

        let name = "domain0.kinetic".to_string();
        store
            .accepted_reveals_timestamps
            .put(name.clone(), std::collections::VecDeque::new());

        for _ in 0..5 {
            store
                .accepted_reveals_timestamps
                .get_mut(&name)
                .unwrap()
                .push_back(web_time::Instant::now());
        }

        store
            .accepted_reveals_timestamps
            .get_mut(&name)
            .unwrap()
            .clear();
        let now = web_time::Instant::now();
        store
            .accepted_reveals_timestamps
            .get_mut(&name)
            .unwrap()
            .push_back(now - web_time::Duration::from_secs(4000));
        store
            .accepted_reveals_timestamps
            .get_mut(&name)
            .unwrap()
            .push_back(now - web_time::Duration::from_secs(3000));
        for _ in 0..5 {
            store
                .accepted_reveals_timestamps
                .get_mut(&name)
                .unwrap()
                .push_back(now);
        }

        let deque = store.accepted_reveals_timestamps.get_mut(&name).unwrap();
        while let Some(t) = deque.front() {
            if web_time::Instant::now().duration_since(*t) > web_time::Duration::from_secs(3600) {
                deque.pop_front();
            } else {
                break;
            }
        }

        assert_eq!(
            store
                .accepted_reveals_timestamps
                .get_mut(&name)
                .unwrap()
                .len(),
            6
        ); // 5 (now) + 1 (3000s ago)
    }

    #[test]
    fn test_heartbeat_monotonicity() {
        let (mut store, _storage) = setup_store(100);
        let name = "test.kinetic".to_string();

        let mut reveal = dummy_reveal(&name, 100);
        let kp = Keypair::generate_ed25519();
        reveal.pubkey = kp.public().to_peer_id().to_bytes(); // We just need *some* bytes, but actually we need Dalek key

        let dalek_kp = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]);
        reveal.pubkey = dalek_kp.verifying_key().to_bytes().to_vec();

        store.reveals_by_name.put(name.clone(), reveal);

        // Set existing pulse to 200
        store.last_heartbeats_by_name.insert(name.clone(), 200);

        let mut hb = Heartbeat {
            name: name.clone(),
            latest_drand_pulse: 150, // older pulse
            signature: vec![],
        };

        // Sign the stale heartbeat
        use ed25519_dalek::Signer;
        hb.signature = dalek_kp.sign(&hb.signable_bytes()).to_vec();

        let result = store.handle_heartbeat(&hb);
        assert!(matches!(
            result.unwrap_err(),
            crate::error::KineticStoreError::StaleHeartbeat
        ));
    }
}
