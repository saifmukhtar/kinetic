use std::path::PathBuf;

#[test]
fn test_ephemeral_key_wiping_fallback() {
    // We cannot easily mock ProjectDirs returning None globally in a safe way without
    // messing up environment variables for other parallel tests.
    // However, we can just assert that `load_or_create_keypair` doesn't return a path containing "/tmp/"
    // Oh wait, `load_or_create_keypair` returns `Result<SigningKey>`, not the path.
    // If we unset HOME and XDG_CONFIG_HOME for this thread, ProjectDirs will fail.

    std::env::remove_var("HOME");
    std::env::remove_var("XDG_CONFIG_HOME");
    std::env::remove_var("USERPROFILE"); // Windows
    std::env::remove_var("APPDATA"); // Windows

    // Also ensure KINETIC_KEY_PATH is not set
    std::env::remove_var("KINETIC_KEY_PATH");

    // Now if we call load_or_create_keypair, it should NOT write to /tmp/.
    // Let's call it and see where it writes... wait, we can't easily intercept the file write.
    // Instead we can just check if /tmp/kinetic_id.bin exists before, delete it, run, and check if it was created!

    let tmp_path = PathBuf::from("/tmp/kinetic_id.bin");
    if tmp_path.exists() {
        std::fs::remove_file(&tmp_path).unwrap();
    }

    // Create the key
    let _ = kinetic_core::types::load_or_create_keypair();

    // Assert it did NOT create the key in /tmp/
    assert!(
        !tmp_path.exists(),
        "SECURITY FLAW: Keypair was written to ephemeral /tmp/ directory!"
    );

    // Clean up
    let fallback_path = std::env::current_dir().unwrap().join(".kinetic/id.bin");
    if fallback_path.exists() {
        std::fs::remove_file(&fallback_path).unwrap();
    }
}
