use kinetic_core::traits::StorageEngine;
use kinetic_storage::KineticStorage;
use proptest::prelude::*;
use tempfile::tempdir;

#[derive(Debug, Clone)]
enum StorageOp {
    Put(Vec<u8>, Vec<u8>),
    Get(Vec<u8>),
    Delete(Vec<u8>),
    ScanPrefix(Vec<u8>),
}

fn arbitrary_storage_op() -> impl Strategy<Value = StorageOp> {
    prop_oneof![
        (any::<Vec<u8>>(), any::<Vec<u8>>()).prop_map(|(k, v)| StorageOp::Put(k, v)),
        any::<Vec<u8>>().prop_map(StorageOp::Get),
        any::<Vec<u8>>().prop_map(StorageOp::Delete),
        any::<Vec<u8>>().prop_map(StorageOp::ScanPrefix),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    #[test]
    fn test_random_storage_operations(
        ops in prop::collection::vec(arbitrary_storage_op(), 1..100)
    ) {
        let dir = tempdir().unwrap();
        let storage = KineticStorage::new(dir.path()).unwrap();

        for op in ops {
            match op {
                StorageOp::Put(k, v) => {
                    let _ = storage.put(&k, &v);
                }
                StorageOp::Get(k) => {
                    let _ = storage.get(&k);
                }
                StorageOp::Delete(k) => {
                    let _ = storage.delete(&k);
                }
                StorageOp::ScanPrefix(prefix) => {
                    let _ = storage.scan_prefix(&prefix, None);
                }
            }
        }
    }
}
