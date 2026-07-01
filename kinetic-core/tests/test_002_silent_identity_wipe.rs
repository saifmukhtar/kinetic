use std::env;
use std::fs;

#[test]
fn test_002_silent_identity_wipe() {
    // 1. Setup a temporary directory for our corrupted identity file
    let temp_dir = env::temp_dir().join("kinetic_test_002");
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();

    let id_file = temp_dir.join("id.bin");

    // 2. Create a corrupted id.bin (e.g. 10 bytes instead of 32)
    fs::write(&id_file, b"corrupted1").unwrap();

    // 3. Set the environment variable so `load_or_create_keypair` uses our test file
    env::set_var("KINETIC_KEY_PATH", &id_file);

    // 4. Attempt to load the keypair.
    // Under the OLD logic (flawed), this would silently overwrite id.bin with a new 32-byte key
    // and return Ok().
    // Under the NEW logic (fixed), this should return an Err() so the user knows it's corrupted.

    let result = kinetic_core::types::load_or_create_keypair();

    // Check if the file was silently overwritten
    let file_size_after = fs::metadata(&id_file).unwrap().len();

    // Cleanup env early to avoid side-effects
    env::remove_var("KINETIC_KEY_PATH");

    // The test EXPECTS that it should return an error.
    assert!(
        result.is_err(),
        "SECURITY FLAW: load_or_create_keypair silently ignored corruption and succeeded!"
    );

    // The test EXPECTS that the file should not have been overwritten.
    assert_eq!(
        file_size_after, 10,
        "SECURITY FLAW: load_or_create_keypair silently overwrote the corrupted file!"
    );

    // Cleanup
    let _ = fs::remove_dir_all(&temp_dir);
}
