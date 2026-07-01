use kinetic_core::traits::StorageEngine;
use kinetic_storage::SledStorage;
use std::time::Instant;
use tempfile::tempdir;

#[test]
fn test_007_async_disk_io_block() {
    let dir = tempdir().unwrap();
    let storage = SledStorage::new(dir.path()).unwrap();

    let start = Instant::now();
    for i in 0..100 {
        let key = format!("key_{}", i);
        storage.put(key.as_bytes(), b"test_value").unwrap();
    }
    let duration = start.elapsed();

    // Under OLD logic, 100 synchronous flushes would block the thread for >50ms (often >200ms)
    // Under NEW logic (removing flush), 100 memory-only writes should take <5ms
    assert!(
        duration.as_millis() < 50,
        "SECURITY FLAW: Storage I/O is still synchronously blocking! 100 puts took {} ms",
        duration.as_millis()
    );
}
