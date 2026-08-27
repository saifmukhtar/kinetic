#[cfg(test)]
mod tests {
    use crate::store::core::KineticRecordStore;
    use kinetic_core::types::{Reveal, VdfProof};
    use kinetic_storage::KineticStorage;
    use libp2p::PeerId;
    use libp2p::identity::Keypair;
    use std::sync::Arc;
    use tempfile::tempdir;

    fn dummy_reveal(name: &str, kyn: u64) -> Reveal {
        Reveal {
            protocol_version: 1,
            name: name.to_string(),
            payload: vec![],
            salt: [0u8; 32],
            kyn,
            drand_signature: String::new(),
            iterations: 100,
            vdf_proof: VdfProof {
                proof_bytes: vec![],
            },
            pubkey: vec![],
            signature: vec![],
            previous_proof: None,
            miner_pubkey: None,
            authorization: None,
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
            Arc::new(KineticStorage::new(dir.path()).unwrap());
        let peer_id = PeerId::from(Keypair::generate_ed25519().public());
        let vdf_engine: Arc<dyn kinetic_core::traits::VdfEngine> =
            Arc::new(kinetic_vdf_rsa::RsaVdfEngine::new());
        let store = KineticRecordStore::new(
            peer_id,
            storage.clone(),
            100, // initial drand kyn
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
        let ml_kp = kinetic_primitives::keys::KineticKeypair::generate();
        reveal.pubkey = ml_kp.pubkey_bytes();

        store.reveals_by_name.put(
            name.clone(),
            kinetic_core::types::NameRecord::Standard(Box::new(reveal)),
        );

        // Set existing kyn to 200
        store.last_heartbeats_by_name.insert(name.clone(), 200);

        let mut hb = kinetic_core::types::Heartbeat {
            name: name.clone(),
            latest_kyn: 49,
            signature: vec![],
            authorization: None,
        };

        // Sign the stale heartbeat
        hb.signature = ml_kp
            .sign(&hb.signable_bytes(kinetic_core::constants::NETWORK_SALT));

        let result = store.handle_process_heartbeat(&hb);
        assert!(matches!(
            result.unwrap_err(),
            crate::error::KineticStoreError::StaleHeartbeat
        ));
    }

    #[test]
    fn test_immutable_name_tie_broken() {
        let (mut store, _storage) = setup_store(100);
        let name = "gov.kin".to_string();

        let existing = kinetic_core::types::NameRecord::Prime {
            name: name.clone(),
            pubkey: vec![1, 2, 3],
            granted_at: 0,
            payload: vec![],
            signature: vec![],
            authorization: None,
        };
        store.reveals_by_name.put(name.clone(), existing);

        let new_reveal =
            kinetic_core::types::NameRecord::Standard(Box::new(dummy_reveal(&name, 100)));
        let result = store.handle_put_record(&new_reveal, true);

        assert!(matches!(
            result.unwrap_err(),
            crate::error::KineticStoreError::ImmutableName
        ));
    }

    #[test]
    fn test_future_heartbeat() {
        let (mut store, _storage) = setup_store(100);
        let name = "test.kin".to_string();

        let mut reveal = dummy_reveal(&name, 100);
        let ml_kp = kinetic_primitives::keys::KineticKeypair::generate();
        reveal.pubkey = ml_kp.pubkey_bytes();

        store.reveals_by_name.put(
            name.clone(),
            kinetic_core::types::NameRecord::Standard(Box::new(reveal)),
        );
        store.last_heartbeats_by_name.insert(name.clone(), 100);

        let mut hb = kinetic_core::types::Heartbeat {
            name: name.clone(),
            latest_kyn: 105,
            signature: vec![],
            authorization: None,
        };

        hb.signature = ml_kp
            .sign(&hb.signable_bytes(kinetic_core::constants::NETWORK_SALT));

        let result = store.handle_process_heartbeat(&hb);
        assert!(matches!(
            result.unwrap_err(),
            crate::error::KineticStoreError::FutureHeartbeat
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_xor_tie_breaker_logic() {
        let (mut store, _storage) = setup_store(100);
        let name = "tie.kin".to_string();

        let mut existing = dummy_reveal(&name, 100);
        existing.pubkey = vec![0x00];
        existing.vdf_proof.proof_bytes = vec![0x01];
        existing.iterations = 1000;
        store.reveals_by_name.put(
            name.clone(),
            kinetic_core::types::NameRecord::Standard(Box::new(existing)),
        );
        store.last_heartbeats_by_name.insert(name.clone(), 100);

        let mut attacker_lose = dummy_reveal(&name, 100);
        attacker_lose.pubkey = vec![0x01];
        attacker_lose.vdf_proof.proof_bytes = vec![0x03]; // XOR = 2
        attacker_lose.vdf_proof.proof_bytes = vec![0x02];
        attacker_lose.iterations = 1000;

        let result_lose = store.handle_put_record(
            &kinetic_core::types::NameRecord::Standard(Box::new(attacker_lose)),
            true,
        );
        assert!(matches!(
            result_lose.unwrap_err(),
            crate::error::KineticStoreError::TieBroken
        ));

        let mut attacker_win = dummy_reveal(&name, 100);
        attacker_win.pubkey = vec![0x01];
        attacker_win.vdf_proof.proof_bytes = vec![0x01]; // XOR = 0
        attacker_win.vdf_proof.proof_bytes = vec![0x00];
        attacker_win.iterations = 1000;

        let result_win = store.handle_put_record(
            &kinetic_core::types::NameRecord::Standard(Box::new(attacker_win)),
            true,
        );
        assert!(result_win.is_ok());
    }
}
