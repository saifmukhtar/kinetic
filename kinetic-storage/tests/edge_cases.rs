use kinetic_core::traits::StorageEngine;
use kinetic_storage::KineticStorage;
use std::sync::Arc;
use tempfile::tempdir;

#[test]
fn test_put_empty_key() {
    let dir = tempdir().unwrap();
    let storage = KineticStorage::new(dir.path()).unwrap();
    storage.put(b"", b"value").unwrap();
    assert_eq!(storage.get(b"").unwrap().unwrap(), &b"value"[..]);
}

#[test]
fn test_put_empty_value() {
    let dir = tempdir().unwrap();
    let storage = KineticStorage::new(dir.path()).unwrap();
    storage.put(b"key", b"").unwrap();
    assert_eq!(storage.get(b"key").unwrap().unwrap(), &b""[..]);
}

#[test]
fn test_get_nonexistent_key() {
    let dir = tempdir().unwrap();
    let storage = KineticStorage::new(dir.path()).unwrap();
    assert_eq!(storage.get(b"missing").unwrap(), None);
}

#[test]
fn test_delete_nonexistent_key() {
    let dir = tempdir().unwrap();
    let storage = KineticStorage::new(dir.path()).unwrap();
    // deleting a non-existent key should succeed or do nothing
    storage.delete(b"missing").unwrap();
}

#[test]
fn test_delete_empty_key() {
    let dir = tempdir().unwrap();
    let storage = KineticStorage::new(dir.path()).unwrap();
    storage.put(b"", b"val").unwrap();
    storage.delete(b"").unwrap();
    assert_eq!(storage.get(b"").unwrap(), None);
}

#[test]
fn test_scan_empty_prefix() {
    let dir = tempdir().unwrap();
    let storage = KineticStorage::new(dir.path()).unwrap();
    storage.put(b"a", b"1").unwrap();
    storage.put(b"b", b"2").unwrap();

    let mut res = storage.scan_prefix(b"", None).unwrap();
    res.sort();
    assert_eq!(res.len(), 2);
    assert_eq!(res[0].0, b"a");
    assert_eq!(res[1].0, b"b");
}

#[test]
fn test_scan_nonexistent_prefix() {
    let dir = tempdir().unwrap();
    let storage = KineticStorage::new(dir.path()).unwrap();
    storage.put(b"a", b"1").unwrap();

    let res = storage.scan_prefix(b"z", None).unwrap();
    assert!(res.is_empty());
}

#[test]
fn test_overwrite_key() {
    let dir = tempdir().unwrap();
    let storage = KineticStorage::new(dir.path()).unwrap();
    storage.put(b"key", b"val1").unwrap();
    storage.put(b"key", b"val2").unwrap();
    assert_eq!(storage.get(b"key").unwrap().unwrap(), &b"val2"[..]);
}

#[test]
fn test_large_key() {
    let dir = tempdir().unwrap();
    let storage = KineticStorage::new(dir.path()).unwrap();
    let large_key = vec![0x41; 2048]; // 2KB key
    storage.put(&large_key, b"val").unwrap();
    assert_eq!(storage.get(&large_key).unwrap().unwrap(), &b"val"[..]);
}

#[test]
fn test_large_value() {
    let dir = tempdir().unwrap();
    let storage = KineticStorage::new(dir.path()).unwrap();
    let large_value = vec![0x42; 1024 * 1024]; // 1MB value
    storage.put(b"key", &large_value).unwrap();
    assert_eq!(storage.get(b"key").unwrap().unwrap(), large_value);
}

#[test]
fn test_scan_order() {
    let dir = tempdir().unwrap();
    let storage = KineticStorage::new(dir.path()).unwrap();
    // Insert out of order
    storage.put(b"p:3", b"3").unwrap();
    storage.put(b"p:1", b"1").unwrap();
    storage.put(b"p:2", b"2").unwrap();

    let res = storage.scan_prefix(b"p:", None).unwrap();
    // The database scan_prefix returns items in lexicographic order
    assert_eq!(res.len(), 3);
    assert_eq!(res[0].0, b"p:1");
    assert_eq!(res[1].0, b"p:2");
    assert_eq!(res[2].0, b"p:3");
}

#[test]
fn test_scan_deleted_key_exclusion() {
    let dir = tempdir().unwrap();
    let storage = KineticStorage::new(dir.path()).unwrap();
    storage.put(b"p:1", b"1").unwrap();
    storage.put(b"p:2", b"2").unwrap();
    storage.delete(b"p:1").unwrap();

    let res = storage.scan_prefix(b"p:", None).unwrap();
    assert_eq!(res.len(), 1);
    assert_eq!(res[0].0, b"p:2");
}

#[test]
fn test_concurrency_reads_writes() {
    use std::thread;

    let dir = tempdir().unwrap();
    let storage = Arc::new(KineticStorage::new(dir.path()).unwrap());

    let mut handles = vec![];
    for i in 0..10 {
        let storage_clone = storage.clone();
        handles.push(thread::spawn(move || {
            let key = format!("thread_key_{}", i);
            storage_clone.put(key.as_bytes(), b"val").unwrap();
            let val = storage_clone.get(key.as_bytes()).unwrap().unwrap();
            assert_eq!(val, &b"val"[..]);
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    let all_keys = storage.scan_prefix(b"thread_key_", None).unwrap();
    assert_eq!(all_keys.len(), 10);
}

#[test]
fn test_multiple_prefixes() {
    let dir = tempdir().unwrap();
    let storage = KineticStorage::new(dir.path()).unwrap();
    storage.put(b"a:1", b"v").unwrap();
    storage.put(b"b:1", b"v").unwrap();
    storage.put(b"a:2", b"v").unwrap();

    let a_keys = storage.scan_prefix(b"a:", None).unwrap();
    assert_eq!(a_keys.len(), 2);

    let b_keys = storage.scan_prefix(b"b:", None).unwrap();
    assert_eq!(b_keys.len(), 1);
}

#[test]
fn test_put_get_binary_data() {
    let dir = tempdir().unwrap();
    let storage = KineticStorage::new(dir.path()).unwrap();
    let binary_data = vec![0x00, 0xFF, 0xFE, 0x01, 0x00];
    storage.put(b"bin", &binary_data).unwrap();
    assert_eq!(storage.get(b"bin").unwrap().unwrap(), binary_data);
}

#[test]
fn test_scan_prefix_with_limit() {
    let dir = tempdir().unwrap();
    let storage = KineticStorage::new(dir.path()).unwrap();
    storage.put(b"p:1", b"1").unwrap();
    storage.put(b"p:2", b"2").unwrap();
    storage.put(b"p:3", b"3").unwrap();
    storage.put(b"p:4", b"4").unwrap();

    let res = storage.scan_prefix(b"p:", Some(2)).unwrap();
    assert_eq!(res.len(), 2);
    assert_eq!(res[0].0, b"p:1");
    assert_eq!(res[1].0, b"p:2");
}

#[test]
fn test_nested_directory_creation() {
    let dir = tempdir().unwrap();
    // Intentionally create a path that does not exist yet (3 levels deep)
    let deep_path = dir.path().join("level1").join("level2").join("level3");

    // This should automatically create the directory tree without throwing an OpenFailed error
    let storage = KineticStorage::new(&deep_path).unwrap();

    storage.put(b"test", b"success").unwrap();
    assert_eq!(storage.get(b"test").unwrap().unwrap(), &b"success"[..]);

    // Verify the file was actually created in that deep directory
    assert!(deep_path.join("state.redb").exists());
}

#[test]
fn test_concurrent_scan_and_write() {
    use std::thread;

    let dir = tempdir().unwrap();
    let storage = Arc::new(KineticStorage::new(dir.path()).unwrap());

    // Pre-populate some data for the scanner
    for i in 0..100 {
        storage
            .put(format!("scan:{}", i).as_bytes(), b"data")
            .unwrap();
    }

    let storage_clone = storage.clone();

    // Thread 1: Constantly hammer the DB with writes
    let writer = thread::spawn(move || {
        for i in 0..500 {
            storage_clone
                .put(format!("write:{}", i).as_bytes(), b"new_data")
                .unwrap();
        }
    });

    // Thread 2 (Main): Run a scan simultaneously
    // The storage engine guarantees isolated read transactions, so the scan should succeed
    // and not crash or deadlock, even though another thread is holding write transactions.
    let mut successful_scans = 0;
    for _ in 0..50 {
        let res = storage.scan_prefix(b"scan:", None).unwrap();
        assert_eq!(res.len(), 100); // The original 100 items should always be present
        successful_scans += 1;
    }

    writer.join().unwrap();

    assert_eq!(successful_scans, 50);
}
