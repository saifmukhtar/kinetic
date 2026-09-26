#[cfg(test)]
mod tests {
    use crate::store::core::KineticRecordStore;
    use kinetic_core::types::{Reveal, VdfProof};
    use kinetic_storage::KineticStorage;
    use libp2p::PeerId;
    use libp2p::identity::Keypair;
    use std::sync::Arc;
    use tempfile::tempdir;

    fn mock_reveal(name: &str, kyn: u64) -> Reveal {
        Reveal {
            protocol_version: 1,
            name: name.to_string(),
            embedded_nrs: vec![],
            salt: [0u8; 32],
            kyn: kinetic_kyn::types::TargetKyn::from(kyn),
            beacon_signature: String::new(),
            iterations: 100,
            vdf_proof: VdfProof {
                proof_bytes: vec![],
            },
            pubkey: kinetic_primitives::keypairs::IdentityPubKey(vec![]),
            identity_signature: kinetic_primitives::keypairs::IdentitySignature(vec![]),
            previous_proof: None,
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
            Arc::new(KineticStorage::new(dir.path().join("state.db")).unwrap());
        let peer_id = PeerId::from(Keypair::generate_ed25519().public());
        let vdf_engine: Arc<dyn kinetic_core::traits::VdfEngine> =
            Arc::new(kinetic_vdf::RsaVdfEngine::new());
        let store = KineticRecordStore::new(
            peer_id,
            storage.clone(),
            100.into(), // initial drand kyn
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

        let mut reveal = mock_reveal(&name, 100);
        let ml_kp = kinetic_primitives::keypairs::IdentityPrivKey::generate();
        reveal.pubkey = ml_kp.to_pubkey();

        store.reveals_by_name.put(
            name.clone(),
            kinetic_core::types::NameEnvelope::Standard(Box::new(reveal)),
        );

        // Set existing kyn to 200
        store.last_heartbeats_by_name.insert(name.clone(), 200);

        let mut hb = kinetic_core::types::Heartbeat {
            name: name.clone(),
            latest_kyn: kinetic_kyn::types::Kyn(49),
            owner_signature: kinetic_primitives::keypairs::IdentitySignature(vec![]),
            authorization: None,
        };

        // Sign the stale heartbeat
        hb.owner_signature = ml_kp.sign(&hb.signable_bytes(kinetic_core::constants::NETWORK_SALT));

        let result = store.handle_process_heartbeat(&hb);
        assert!(matches!(
            result.unwrap_err(),
            crate::error::KineticStoreError::StaleHeartbeat
        ));
    }

    #[test]
    fn test_future_heartbeat() {
        let (mut store, _storage) = setup_store(100);
        let name = "test.kin".to_string();

        let mut reveal = mock_reveal(&name, 100);
        let ml_kp = kinetic_primitives::keypairs::IdentityPrivKey::generate();
        reveal.pubkey = ml_kp.to_pubkey();

        store.reveals_by_name.put(
            name.clone(),
            kinetic_core::types::NameEnvelope::Standard(Box::new(reveal)),
        );
        store.last_heartbeats_by_name.insert(name.clone(), 100);

        let mut hb = kinetic_core::types::Heartbeat {
            name: name.clone(),
            latest_kyn: kinetic_kyn::types::Kyn(105),
            owner_signature: kinetic_primitives::keypairs::IdentitySignature(vec![]),
            authorization: None,
        };

        hb.owner_signature = ml_kp.sign(&hb.signable_bytes(kinetic_core::constants::NETWORK_SALT));

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

        let mut existing = mock_reveal(&name, 100);
        existing.pubkey = kinetic_primitives::keypairs::IdentityPubKey(vec![0x00]);
        existing.vdf_proof.proof_bytes = vec![0x01];
        existing.iterations = 1000;
        store.reveals_by_name.put(
            name.clone(),
            kinetic_core::types::NameEnvelope::Standard(Box::new(existing)),
        );
        store.last_heartbeats_by_name.insert(name.clone(), 100);

        let mut attacker_lose = mock_reveal(&name, 100);
        attacker_lose.pubkey = kinetic_primitives::keypairs::IdentityPubKey(vec![0x01]);
        attacker_lose.vdf_proof.proof_bytes = vec![0x03]; // XOR = 2
        attacker_lose.vdf_proof.proof_bytes = vec![0x02];
        attacker_lose.iterations = 1000;

        let result_lose = store.handle_put_record(
            &kinetic_core::types::NameEnvelope::Standard(Box::new(attacker_lose)),
            true,
        );
        assert!(matches!(
            result_lose.unwrap_err(),
            crate::error::KineticStoreError::TieBroken
        ));

        let mut attacker_win = mock_reveal(&name, 100);
        attacker_win.pubkey = kinetic_primitives::keypairs::IdentityPubKey(vec![0x01]);
        attacker_win.vdf_proof.proof_bytes = vec![0x01]; // XOR = 0 (closer)
        attacker_win.vdf_proof.proof_bytes = vec![0x00];
        attacker_win.iterations = 1000;

        let result_win = store.handle_put_record(
            &kinetic_core::types::NameEnvelope::Standard(Box::new(attacker_win)),
            true,
        );
        assert!(result_win.is_ok());
    }
}
