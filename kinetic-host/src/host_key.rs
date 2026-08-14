//! Static host identity key loader and atomic disk persistence engine.

use libp2p::identity::Keypair;
use std::path::PathBuf;

/// Loads static Ed25519 host identity from disk, or generates a new one if missing or corrupted.
pub fn load_or_generate_host_key(key_path: &PathBuf) -> Keypair {
    if let Some(parent) = key_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(bytes) = std::fs::read(key_path) {
        tracing::info!("Loaded static infrastructure identity from disk");
        Keypair::from_protobuf_encoding(&bytes).unwrap_or_else(|_| {
            tracing::warn!("Corrupted static identity found, generating new one");
            let k = Keypair::generate_ed25519();
            if let Ok(encoded) = k.to_protobuf_encoding()
                && let Err(e) = write_secret(key_path, &encoded)
            {
                tracing::warn!("Failed to save static infrastructure identity: {}", e);
            }
            k
        })
    } else {
        let k = Keypair::generate_ed25519();
        if let Ok(encoded) = k.to_protobuf_encoding()
            && let Err(e) = write_secret(key_path, &encoded)
        {
            tracing::warn!("Failed to save static infrastructure identity: {}", e);
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
