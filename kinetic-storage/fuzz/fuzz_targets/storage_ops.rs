//! libFuzzer target testing `KineticStorage` operations against arbitrary key/value payloads and random operation sequences.

#![no_main]

use libfuzzer_sys::fuzz_target;
use kinetic_storage::KineticStorage;
use kinetic_core::traits::StorageEngine;
use std::sync::OnceLock;
use std::sync::Arc;
use tempfile::TempDir;

static KINETIC_STORAGE: OnceLock<(Arc<KineticStorage>, TempDir)> = OnceLock::new();

fuzz_target!(|data: &[u8]| {
    // 1. Initialize the global storage instance
    let (storage, _temp_dir) = KINETIC_STORAGE.get_or_init(|| {
        let temp_dir = TempDir::new().unwrap();
        let storage = Arc::new(KineticStorage::new(temp_dir.path()).unwrap());
        (storage, temp_dir)
    });

    let mut cursor = 0;

    // 2. STATEFUL SEQUENCE FUZZING: Chunk the data and execute multiple sequential ops
    while cursor + 3 <= data.len() {
        let op_code = data[cursor] % 4;
        let meta = data[cursor + 1]; // Used for limits or splitting
        let payload_len = data[cursor + 2] as usize;
        cursor += 3;

        // Ensure we don't read out of bounds
        if cursor + payload_len > data.len() {
            break;
        }

        let payload = &data[cursor..cursor + payload_len];
        cursor += payload_len;

        match op_code {
            0 => {
                // 3. ASYMMETRIC PAYLOAD SPLITTING: Use `meta` to randomly slice the payload
                let split_idx = if payload_len > 0 {
                    (meta as usize) % (payload_len + 1)
                } else {
                    0
                };
                let key = &payload[..split_idx];
                let val = &payload[split_idx..];
                
                // This correctly tests extreme edge cases (empty keys + massive values, etc)
                let _ = storage.put(key, val);
            }
            1 => {
                // Get
                let _ = storage.get(payload);
            }
            2 => {
                // Delete
                let _ = storage.delete(payload);
            }
            _ => {
                // 4. LIMIT FUZZING: Use `meta` to inject bounds constraints to test Kademlia DHT logic
                let limit = if meta == 0 { None } else { Some(meta as usize) };
                let _ = storage.scan_prefix(payload, limit);
            }
        }
    }
});
