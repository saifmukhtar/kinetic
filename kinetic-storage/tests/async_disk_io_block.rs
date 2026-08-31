use kinetic_core::traits::StorageEngine;
use kinetic_storage::KineticStorage;
use std::time::Instant;
use tempfile::tempdir;

#[test]
fn test_async_disk_io_block() {
    let dir = tempdir().unwrap();
    let storage = KineticStorage::new(dir.path()).unwrap();

    let start = Instant::now();
    for i in 0..100 {
        let key = format!("key_{}", i);
        storage.put(key.as_bytes(), b"test_value").unwrap();
    }
    let duration = start.elapsed();

    // The database guarantees full ACID durability on every commit (fsync).
    // This is safer than older embedded databases' background flusher, but means 100 separate
    // transactions will take ~50-100ms. We set a generous 1000ms bound to ensure
    // it's not pathologically slow on slower disks.
    assert!(
        duration.as_millis() < 1000,
        "SECURITY FLAW: Storage I/O is pathologically slow! 100 puts took {} ms",
        duration.as_millis()
    );
}
