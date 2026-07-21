#![no_main]

use libfuzzer_sys::fuzz_target;
use libp2p::kad;
use kinetic_network::store::core::KineticRecordStore;
use kinetic_storage::SledStorage;
use libp2p::identity::Keypair;
use std::sync::Arc;
use std::num::NonZeroUsize;
use std::sync::OnceLock;
use tempfile::TempDir;

static SLED_STORAGE: OnceLock<(Arc<SledStorage>, TempDir)> = OnceLock::new();

fuzz_target!(|data: &[u8]| {
    let (storage, _temp_dir) = SLED_STORAGE.get_or_init(|| {
        let temp_dir = TempDir::new().unwrap();
        let storage = Arc::new(SledStorage::new(temp_dir.path()).unwrap());
        (storage, temp_dir)
    });

    let local_peer_id = Keypair::generate_ed25519().public().to_peer_id();
    let mut store = KineticRecordStore::new(
        local_peer_id,
        Arc::clone(&storage) as Arc<dyn kinetic_core::traits::StorageEngine>,
        0,
        NonZeroUsize::new(1024).unwrap(),
        1000,
        Arc::new(kinetic_vdf::ChiaVdfEngine) as Arc<dyn kinetic_core::traits::VdfEngine>,
    );

    let key = kad::RecordKey::new(&"fuzz_key");
    let record = kad::Record::new(key, data.to_vec());
    let _ = store.put_record(record);
});
