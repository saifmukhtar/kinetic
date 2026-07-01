use kinetic_storage::SledStorage;
use tempfile::tempdir;

#[test]
fn test_008_locked_database_ux() {
    let dir = tempdir().unwrap();

    // First instance acquires the Sled lock
    let _storage1 = SledStorage::new(dir.path()).unwrap();

    // Second instance tries to open the same database concurrently
    let storage2_result = SledStorage::new(dir.path());

    let err_msg = match storage2_result {
        Ok(_) => panic!("Second storage instance should fail to open!"),
        Err(e) => e.to_string(),
    };

    // Under OLD logic, the error is a raw Sled IO error (e.g., "IO error: Resource temporarily unavailable")
    // Under NEW logic, the UX should be clear and helpful
    assert!(
        err_msg.contains("Another instance of Kinetic daemon is already running"),
        "SECURITY FLAW: Did not provide a clear UX message for locked database! Error was: {}",
        err_msg
    );
}
