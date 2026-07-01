use kinetic_core::traits::StorageEngine;
use kinetic_storage::SledStorage;
use std::fs;
use std::path::PathBuf;
use tempfile::tempdir;

#[test]
fn test_006_sled_corruption_recovery() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("storage_db");

    // To guarantee sled::open fails, we create a directory where it expects its main database file
    fs::create_dir_all(&db_path).unwrap();
    let corrupt_file = db_path.join("db");
    fs::create_dir(&corrupt_file).unwrap();

    // Under OLD logic, SledStorage::new would return an Err here and the daemon would crash/loop
    // Under NEW logic, SledStorage::new should catch the error, rename the dir to storage_db.corrupt.bak, and create a fresh db
    let storage_result = SledStorage::new(&db_path);

    assert!(
        storage_result.is_ok(),
        "SECURITY FLAW: Sled corruption was not auto-recovered. The node is stuck in a boot loop!"
    );

    let storage = storage_result.unwrap();

    // Verify we can write to the fresh db
    storage.put(b"test_key", b"test_value").unwrap();
    let res = storage.get(b"test_key").unwrap();
    assert_eq!(res.unwrap(), b"test_value");

    // Verify the .bak directory was created
    let mut bak_path = db_path.clone().into_os_string();
    bak_path.push(".corrupt.bak");
    let bak_path = PathBuf::from(bak_path);

    assert!(
        bak_path.exists(),
        "The corrupted database was not moved to a backup directory!"
    );
}
