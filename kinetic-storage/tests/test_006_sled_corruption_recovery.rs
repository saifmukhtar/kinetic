use kinetic_core::traits::StorageEngine;
use kinetic_storage::SledStorage;
use std::fs;
use std::path::PathBuf;
use tempfile::tempdir;

#[test]
fn test_006_sled_corruption_recovery() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("storage_db");

    // To guarantee sled::open fails with a Corruption error, we write garbage data to the configuration file
    fs::create_dir_all(&db_path).unwrap();
    let corrupt_file = db_path.join("conf");
    fs::write(
        &corrupt_file,
        b"this is completely invalid garbage data for sled",
    )
    .unwrap();

    // Under NEW security rules, SledStorage::new should fail closed (return Err)
    // but still back up the corrupt database with a timestamp.
    let storage_result = SledStorage::new(&db_path);

    assert!(
        storage_result.is_err(),
        "SECURITY FLAW: Sled corruption should fail closed, not silently recover!"
    );

    // Verify a .bak directory with a timestamp was created
    let parent = db_path.parent().unwrap();
    let entries = fs::read_dir(parent).unwrap();
    
    let mut backup_found = false;
    for entry in entries {
        let entry = entry.unwrap();
        let name = entry.file_name().into_string().unwrap();
        if name.starts_with("storage_db.corrupt.") && name.ends_with(".bak") {
            backup_found = true;
            break;
        }
    }

    assert!(
        backup_found,
        "The corrupted database was not moved to a timestamped backup directory!"
    );
}
