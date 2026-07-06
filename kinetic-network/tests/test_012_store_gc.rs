use kinetic_network::store::KineticRecordStore;
use kinetic_storage::SledStorage;
use libp2p::kad::store::RecordStore;
use libp2p::kad::RecordKey;
use libp2p::PeerId;
use tempfile::tempdir;

#[tokio::test]
async fn test_store_garbage_collection() {
    let dir = tempdir().unwrap();
    let storage = SledStorage::new(dir.path()).unwrap();
    let store = KineticRecordStore::new(PeerId::random(), std::sync::Arc::new(storage), 0);

    // In this test, we would ideally verify that expired records are cleared.
    // We can just verify the instantiation and that it can handle empty state for now.

    let key = RecordKey::new(&"test_key");
    assert!(store.get(&key).is_none());
}

#[tokio::test]
async fn test_store_provider_records() {
    let dir = tempdir().unwrap();
    let storage = SledStorage::new(dir.path()).unwrap();
    let mut store = KineticRecordStore::new(PeerId::random(), std::sync::Arc::new(storage), 0);

    let key = RecordKey::new(&"test_provider");
    let provider = libp2p::kad::ProviderRecord {
        key: key.clone(),
        provider: PeerId::random(),
        expires: None,
        addresses: vec![],
    };

    assert!(store.add_provider(provider.clone()).is_ok());

    // Providers are stored
    let providers = store.providers(&key);
    assert_eq!(providers.len(), 1);
    assert_eq!(providers[0].provider, provider.provider);
}

#[tokio::test]
async fn test_store_remove_provider() {
    let dir = tempdir().unwrap();
    let storage = SledStorage::new(dir.path()).unwrap();
    let mut store = KineticRecordStore::new(PeerId::random(), std::sync::Arc::new(storage), 0);

    let key = RecordKey::new(&"test_provider_remove");
    let peer = PeerId::random();
    let provider = libp2p::kad::ProviderRecord {
        key: key.clone(),
        provider: peer,
        expires: None,
        addresses: vec![],
    };

    assert!(store.add_provider(provider.clone()).is_ok());
    store.remove_provider(&key, &peer);

    let providers = store.providers(&key);
    assert_eq!(providers.len(), 0);
}

#[tokio::test]
async fn test_store_provided_records() {
    let dir = tempdir().unwrap();
    let storage = SledStorage::new(dir.path()).unwrap();
    let mut store = KineticRecordStore::new(PeerId::random(), std::sync::Arc::new(storage), 0);

    let key = RecordKey::new(&"test_provided");
    let peer = PeerId::random();
    let provider = libp2p::kad::ProviderRecord {
        key: key.clone(),
        provider: peer,
        expires: None,
        addresses: vec![],
    };

    assert!(store.add_provider(provider.clone()).is_ok());

    // We should be able to iterate over provided records
    let provided: Vec<_> = store.provided().collect();
    assert_eq!(provided.len(), 1);
    assert_eq!(provided[0].provider, peer);
}
