use crate::governance::Hash256;
use futures_util::StreamExt;
use reqwest::Client;
use sha2::{Digest, Sha256};
use std::env;
use std::io::Write;
use std::process::Command;
use tempfile::NamedTempFile;
use tracing::{error, info, warn};
use web_time::Duration;

/// Downloads and atomically replaces the running binary from one of the given
/// `mirrors`, verifying the download against `expected_hash` (SHA-256).
///
/// The update follows five safety properties:
/// 1. A 60-second request timeout prevents hanging on unresponsive mirrors.
/// 2. The download is streamed chunk-by-chunk to avoid OOM on large binaries.
/// 3. Hash verification is performed before the binary is replaced.
/// 4. The binary is replaced atomically using `self_replace`.
/// 5. The process is re-launched via `exec()`, retaining all CLI arguments.
///
/// Returns an error if all mirrors fail or produce an invalid hash.
pub async fn perform_ota_update(
    self_id: &str,
    manifest_hash: Hash256,
    mirrors: Vec<String>,
) -> Result<(), crate::error::UpdaterError> {
    if mirrors.is_empty() {
        return Err(crate::error::UpdaterError::NoMirrorsProvided);
    }

    let client = Client::builder().timeout(Duration::from_secs(60)).build()?;

    // Load-balance across mirrors by shuffling them deterministically-random per node
    let mut shuffled_mirrors = mirrors;
    let random_state = std::collections::hash_map::RandomState::new();
    shuffled_mirrors.sort_by_cached_key(|url| {
        use std::hash::{BuildHasher, Hasher};
        let mut hasher = random_state.build_hasher();
        hasher.write(url.as_bytes());
        hasher.finish()
    });

    info!("OTA update triggered. Self identity: {}", self_id);

    let mut temp_path = None;

    for mirror in shuffled_mirrors {
        info!("Attempting OTA update from mirror: {}", mirror);

        // 1. Download Manifest
        let manifest_url = format!("{}/manifest.json", mirror);
        let response = match client.get(&manifest_url).send().await {
            Ok(res) if res.status().is_success() => res,
            Ok(res) => {
                warn!(
                    "Mirror {} returned status {} for manifest",
                    mirror,
                    res.status()
                );
                continue;
            }
            Err(e) => {
                warn!("Mirror {} failed to connect for manifest: {}", mirror, e);
                continue;
            }
        };

        let manifest_bytes = match response.bytes().await {
            Ok(b) => b,
            Err(e) => {
                warn!(
                    "Failed to read manifest bytes from mirror {}: {}",
                    mirror, e
                );
                continue;
            }
        };

        // 2. Verify Manifest Hash
        let mut hasher = Sha256::new();
        hasher.update(&manifest_bytes);
        let result_hash = hasher.finalize();
        let mut result_hash_array = [0u8; 32];
        result_hash_array.copy_from_slice(&result_hash);

        if result_hash_array != manifest_hash {
            warn!(
                "Manifest hash verification failed for mirror: {}. Expected: {}, Got: {}",
                mirror,
                hex::encode(manifest_hash),
                hex::encode(result_hash_array)
            );
            continue;
        }

        info!("Manifest hash verified for mirror: {}", mirror);

        // 3. Parse Manifest and lookup target hash
        let manifest: std::collections::HashMap<String, String> =
            match serde_json::from_slice(&manifest_bytes) {
                Ok(m) => m,
                Err(e) => {
                    warn!(
                        "Failed to parse JSON manifest from mirror {}: {}",
                        mirror, e
                    );
                    continue;
                }
            };

        let target_hash_hex = match manifest.get(self_id) {
            Some(h) => h,
            None => {
                info!(
                    "Self identity {} not found in manifest. Skipping update.",
                    self_id
                );
                return Ok(()); // This binary is not targeted for update
            }
        };

        let expected_binary_hash = match hex::decode(target_hash_hex) {
            Ok(bytes) if bytes.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                arr
            }
            _ => {
                warn!(
                    "Invalid target hash hex in manifest for {}: {}",
                    self_id, target_hash_hex
                );
                continue;
            }
        };

        // 4. Download Actual Binary
        let binary_url = format!("{}/{}", mirror, self_id);
        let response = match client.get(&binary_url).send().await {
            Ok(res) if res.status().is_success() => res,
            Ok(res) => {
                warn!(
                    "Mirror {} returned status {} for binary",
                    mirror,
                    res.status()
                );
                continue;
            }
            Err(e) => {
                warn!("Mirror {} failed to connect for binary: {}", mirror, e);
                continue;
            }
        };

        let mut temp_file = match NamedTempFile::new() {
            Ok(f) => f,
            Err(e) => {
                error!("Failed to create temp file: {}", e);
                return Err(e.into());
            }
        };

        let mut hasher = Sha256::new();
        let mut byte_stream = response.bytes_stream();
        let mut download_success = true;

        while let Some(chunk_result) = byte_stream.next().await {
            match chunk_result {
                Ok(chunk) => {
                    hasher.update(&chunk);
                    if let Err(e) = temp_file.write_all(&chunk) {
                        error!("Failed to write chunk to temp file: {}", e);
                        download_success = false;
                        break;
                    }
                }
                Err(e) => {
                    warn!(
                        "Failed to stream binary chunk from mirror {}: {}",
                        mirror, e
                    );
                    download_success = false;
                    break;
                }
            }
        }

        if !download_success {
            continue;
        }

        let result_hash = hasher.finalize();
        let mut result_hash_array = [0u8; 32];
        result_hash_array.copy_from_slice(&result_hash);

        if result_hash_array == expected_binary_hash {
            info!("Binary hash verification successful for mirror: {}", mirror);
            temp_path = Some(temp_file.into_temp_path());
            break;
        } else {
            warn!(
                "Binary hash verification failed for mirror: {}. Expected: {}, Got: {}",
                mirror,
                hex::encode(expected_binary_hash),
                hex::encode(result_hash_array)
            );
        }
    }

    let temp_path = match temp_path {
        Some(path) => path,
        None => {
            return Err(crate::error::UpdaterError::NetworkError(
                "All mirrors failed, or provided invalid hashes/manifests.".to_string(),
            ));
        }
    };

    info!("Overwriting running binary...");
    if let Err(e) = self_replace::self_replace(&temp_path) {
        error!(
            "OTA Update Failed: Permission Denied or File Locked. Error: {}",
            e
        );
        return Err(e.into());
    }

    let current_exe = match env::current_exe() {
        Ok(exe) => exe,
        Err(e) => {
            error!("Failed to get current executable path: {}", e);
            return Err(e.into());
        }
    };

    let args: Vec<String> = env::args().skip(1).collect();

    #[cfg(unix)]
    {
        info!("Baton Pass: Atomically replacing process image via exec()...");
        use std::os::unix::process::CommandExt;
        let err = Command::new(current_exe).args(&args).exec();
        error!("CRITICAL: self_replace succeeded but exec failed: {}", err);
        Err(crate::error::UpdaterError::SpawnFailed(err.to_string()))
    }

    #[cfg(not(unix))]
    {
        info!("Baton Pass: Spawning new process and exiting...");
        match Command::new(current_exe).args(&args).spawn() {
            Ok(_) => {
                std::process::exit(0);
            }
            Err(err) => {
                error!("CRITICAL: self_replace succeeded but spawn failed: {}", err);
                Err(crate::error::UpdaterError::SpawnFailed(err.to_string()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    #[tokio::test]
    async fn test_perform_ota_no_mirrors() {
        let dummy_hash = [0u8; 32];
        let res = perform_ota_update("test-id", dummy_hash, vec![]).await;
        assert!(matches!(
            res,
            Err(crate::error::UpdaterError::NoMirrorsProvided)
        ));
    }

    #[tokio::test]
    async fn test_perform_ota_hash_mismatch() {
        // Spin up a raw TCP server to mock the mirror
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let mirror_url = format!("http://127.0.0.1:{}", port);

        thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0; 1024];
                let _ = stream.read(&mut buf);

                let response = "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nBAD!";
                let _ = stream.write_all(response.as_bytes());
            }
        });

        // We provide a dummy hash that definitely won't match "BAD!"
        let dummy_hash = [1u8; 32];

        let res = perform_ota_update("test-id", dummy_hash, vec![mirror_url]).await;

        // It should try the mirror, get the file, hash it, fail verification, and exhaust all mirrors
        if let Err(crate::error::UpdaterError::NetworkError(msg)) = res {
            assert!(msg.contains("failed, or provided invalid hashes/manifests."));
        } else {
            panic!(
                "Expected NetworkError with invalid hash message, got: {:?}",
                res
            );
        }
    }
}
