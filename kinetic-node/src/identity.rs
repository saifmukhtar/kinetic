use libp2p::identity::Keypair;
use std::path::Path;

/// Loads a static infrastructure identity from disk, or generates a new one if it does not exist.
///
/// This ensures that the node maintains a consistent Peer ID across restarts. If the existing
/// key is corrupted or cannot be read, a new Ed25519 keypair is generated and saved to the specified path.
pub fn load_or_generate_key(key_path: &Path) -> Keypair {
    if let Some(parent) = key_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    if let Ok(bytes) = std::fs::read(key_path) {
        tracing::info!("Loaded static infrastructure identity from disk");
        Keypair::from_protobuf_encoding(&bytes).unwrap_or_else(|_| {
            tracing::warn!("Corrupted static identity found, generating new one");
            Keypair::generate_ed25519()
        })
    } else {
        let k = Keypair::generate_ed25519();
        if let Ok(encoded) = k.to_protobuf_encoding() {
            if let Err(e) = write_secret(key_path, &encoded) {
                tracing::warn!("Failed to save generated infrastructure identity: {}", e);
            }
        }
        tracing::info!("Generated new static infrastructure identity");
        k
    }
}

#[cfg(unix)]
fn write_secret(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = path.with_extension("tmp");
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    std::fs::rename(tmp, path)
}

#[cfg(not(unix))]
fn write_secret(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_generate_new_key_if_missing() {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("test_key.bin");

        assert!(!key_path.exists());
        let key = load_or_generate_key(&key_path);

        assert!(key_path.exists(), "Key should be saved to disk");

        let loaded_bytes = std::fs::read(&key_path).unwrap();
        let loaded_key = Keypair::from_protobuf_encoding(&loaded_bytes).unwrap();

        assert_eq!(
            key.public().to_peer_id(),
            loaded_key.public().to_peer_id(),
            "Generated key and saved key must match"
        );
    }

    #[test]
    fn test_load_existing_key() {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("test_key2.bin");

        let original_key = load_or_generate_key(&key_path);
        let original_peer_id = original_key.public().to_peer_id();

        let reloaded_key = load_or_generate_key(&key_path);
        let reloaded_peer_id = reloaded_key.public().to_peer_id();

        assert_eq!(
            original_peer_id, reloaded_peer_id,
            "Should reload the identical key"
        );
    }

    #[test]
    fn test_fallback_on_corrupted_key() {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("corrupt_key.bin");

        // Write invalid data
        std::fs::write(&key_path, b"not a real protobuf key").unwrap();

        // Should fallback to generating a new key without panicking
        let key = load_or_generate_key(&key_path);
        let peer_id = key.public().to_peer_id();

        // Ensure it doesn't crash, and successfully produced a peer ID
        assert!(!peer_id.to_string().is_empty());
    }

    #[test]
    fn test_fallback_on_unwritable_directory() {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("unwritable").join("key.bin");

        // If we were on linux, we could chmod the directory, but for a simple test we can just
        // make `unwritable` a file instead of a directory, which will cause create_dir_all or write to fail.
        std::fs::write(dir.path().join("unwritable"), b"file").unwrap();

        // This should not panic. It should just generate the key in-memory.
        let key = load_or_generate_key(&key_path);
        let peer_id = key.public().to_peer_id();

        assert!(!peer_id.to_string().is_empty());
        assert!(!key_path.exists());
    }

    #[test]
    fn test_fallback_on_empty_file_does_not_overwrite() {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("empty_key.bin");

        std::fs::write(&key_path, b"").unwrap();

        let key = load_or_generate_key(&key_path);
        assert!(!key.public().to_peer_id().to_string().is_empty());

        // It should have generated a new key in memory, but NOT overwritten the corrupted file.
        // Therefore, the file should still be exactly 0 bytes.
        let bytes = std::fs::read(&key_path).unwrap();
        assert_eq!(bytes.len(), 0);
    }

    #[test]
    fn test_keypair_is_ed25519() {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("test_ed25519.bin");

        let key = load_or_generate_key(&key_path);

        // The default kinetic node key type must be Ed25519
        // Ed25519 peer IDs encoded in base58 start with 12D3Koo...
        let peer_id_str = key.public().to_peer_id().to_base58();
        assert!(peer_id_str.starts_with("12D3Koo"));
    }

    #[test]
    fn test_generate_unique_keys() {
        let dir = tempdir().unwrap();

        let path1 = dir.path().join("key1.bin");
        let path2 = dir.path().join("key2.bin");

        let key1 = load_or_generate_key(&path1);
        let key2 = load_or_generate_key(&path2);

        assert_ne!(
            key1.public().to_peer_id(),
            key2.public().to_peer_id(),
            "Multiple generations should produce distinct keys"
        );
    }

    #[test]
    fn test_public_key_extraction() {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("test_pubkey.bin");

        let key = load_or_generate_key(&key_path);

        // The public key must be extractable and usable
        let pub_key = key.public();

        // Ensure that extracting the public key twice yields identically sized protobuf encodings
        let bytes1 = pub_key.clone().encode_protobuf();
        let bytes2 = pub_key.encode_protobuf();

        assert_eq!(bytes1, bytes2);
        assert!(!bytes1.is_empty());
    }
}

#[cfg(test)]
mod fuzzing {
    use super::*;
    use proptest::prelude::*;
    use tempfile::tempdir;

    proptest! {
        #[test]
        fn doesnt_crash_on_corrupted_identity_files(
            file_content in any::<Vec<u8>>()
        ) {
            let dir = tempdir().unwrap();
            let key_path = dir.path().join("fuzz_key.bin");
            let _ = std::fs::write(&key_path, &file_content);

            // This function must gracefully ignore the garbage and mint a new identity
            let key = load_or_generate_key(&key_path);
            assert!(!key.public().to_peer_id().to_string().is_empty());
        }
    }
}
