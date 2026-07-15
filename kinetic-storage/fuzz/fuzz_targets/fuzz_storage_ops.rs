#![no_main]

use libfuzzer_sys::fuzz_target;
use kinetic_storage::SledStorage;
use kinetic_core::traits::StorageEngine;
use std::sync::OnceLock;
use std::sync::Arc;
use tempfile::TempDir;

static SLED_STORAGE: OnceLock<(Arc<SledStorage>, TempDir)> = OnceLock::new();

fuzz_target!(|data: &[u8]| {
    // If we don't have enough data to pick an operation and provide key/value, skip.
    if data.len() < 2 {
        return;
    }

    let (storage, _temp_dir) = SLED_STORAGE.get_or_init(|| {
        let temp_dir = TempDir::new().unwrap();
        let storage = Arc::new(SledStorage::new(temp_dir.path()).unwrap());
        (storage, temp_dir)
    });

    // Use the first byte to decide the operation
    let op = data[0] % 4;
    let payload = &data[1..];

    // Split payload in half for key/value if it's a put
    let split_idx = payload.len() / 2;
    let key = &payload[..split_idx];
    let val = &payload[split_idx..];

    match op {
        0 => {
            let _ = storage.put(key, val);
        }
        1 => {
            let _ = storage.get(payload);
        }
        2 => {
            let _ = storage.delete(payload);
        }
        _ => {
            let _ = storage.scan_prefix(payload);
        }
    }
});
