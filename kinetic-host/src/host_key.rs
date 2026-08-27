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
            tracing::warn!("KIN-HOST-011: Corrupted static identity found on disk, generating new one");
            let k = Keypair::generate_ed25519();
            if let Ok(encoded) = k.to_protobuf_encoding()
                && let Err(e) = kinetic_core::secure_fs::write_secret(key_path, &encoded)
            {
                panic!("CRITICAL FATAL ERROR: Cannot save host.key to disk! Check folder permissions. Error: {}", e);
            }
            k
        })
    } else {
        let k = Keypair::generate_ed25519();
        if let Ok(encoded) = k.to_protobuf_encoding()
            && let Err(e) = kinetic_core::secure_fs::write_secret(key_path, &encoded)
        {
            tracing::warn!("KIN-HOST-012: Failed to persist new static infrastructure identity to disk: {}", e);
        }
        tracing::info!("Generated new static infrastructure identity");
        k
    }
}
