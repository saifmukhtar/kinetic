use libp2p::identity::Keypair;
use std::path::PathBuf;

pub fn load_or_generate_host_key(key_path: &PathBuf) -> Keypair {
    if let Some(parent) = key_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(bytes) = std::fs::read(&key_path) {
        tracing::info!("Loaded static infrastructure identity from disk");
        Keypair::from_protobuf_encoding(&bytes).unwrap_or_else(|_| Keypair::generate_ed25519())
    } else {
        let k = Keypair::generate_ed25519();
        if let Ok(encoded) = k.to_protobuf_encoding() {
            if let Err(e) = std::fs::write(&key_path, encoded) {
                tracing::warn!("Failed to save static infrastructure identity: {}", e);
            }
        }
        tracing::info!("Generated new static infrastructure identity");
        k
    }
}
