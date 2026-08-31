use kinetic_storage::KineticStorage;
use std::fs;
use tempfile::tempdir;

#[test]
fn test_db_corruption_recovery() {
    let dir = tempdir().unwrap();
    let db_dir = dir.path().join("storage_db");

    fs::create_dir_all(&db_dir).unwrap();
    let corrupt_file = db_dir.join("state.redb");
    fs::write(
        &corrupt_file,
        b"this is completely invalid garbage data for the database that definitely isn't a valid database file header whatsoever it should be at least a few bytes long",
    )
    .unwrap();

    let storage_result = KineticStorage::new(&db_dir);

    let err_msg = match storage_result {
        Ok(_) => panic!("SECURITY FLAW: Database corruption should fail closed, not silently recover!"),
        Err(e) => e.to_string(),
    };

    assert!(
        err_msg.contains("Database corrupted. Manual recovery required."),
        "SECURITY FLAW: Did not provide the correct UX message for database corruption! Error was: {}",
        err_msg
    );

    let entries = fs::read_dir(dir.path()).unwrap();
    let mut backup_found = false;
    for entry in entries {
        let entry = entry.unwrap();
        let name = entry.file_name().into_string().unwrap();
        println!("FOUND ENTRY: {}", name);
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
