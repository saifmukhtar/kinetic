use crate::governance::Hash256;
use futures_util::StreamExt;
use reqwest::Client;
use sha2::{Digest, Sha256};
use std::env;
use std::io::Write;
use std::process::Command;
use web_time::Duration;
use tempfile::NamedTempFile;
use tracing::{error, info, warn};

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
    expected_hash: Hash256,
    mirrors: Vec<String>,
) -> Result<(), crate::error::UpdaterError> {
    if mirrors.is_empty() {
        return Err(crate::error::UpdaterError::NoMirrorsProvided);
    }

    let client = Client::builder().timeout(Duration::from_secs(60)).build()?;

    let mut temp_path = None;

    for mirror in mirrors {
        info!("Attempting OTA update from mirror: {}", mirror);

        let response = match client.get(&mirror).send().await {
            Ok(res) if res.status().is_success() => res,
            Ok(res) => {
                warn!("Mirror {} returned status: {}", mirror, res.status());
                continue;
            }
            Err(e) => {
                warn!("Mirror {} failed to connect: {}", mirror, e);
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

        // Stream bytes to prevent OOM on large binaries.
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
                    warn!("Failed to stream chunk from mirror {}: {}", mirror, e);
                    download_success = false;
                    break;
                }
            }
        }

        if !download_success {
            continue;
        }

        // Verify the hash; convert to hex for readable logging.
        let result_hash = hasher.finalize();
        let mut result_hash_array = [0u8; 32];
        result_hash_array.copy_from_slice(&result_hash);

        if result_hash_array == expected_hash {
            info!("Hash verification successful for mirror: {}", mirror);
            temp_path = Some(temp_file.into_temp_path());
            break;
        } else {
            let expected_hex = hex::encode(expected_hash);
            let got_hex = hex::encode(result_hash_array);
            warn!(
                "Hash verification failed for mirror: {}. Expected: {}, Got: {}",
                mirror, expected_hex, got_hex
            );
        }
    }

    let temp_path = match temp_path {
        Some(path) => path,
        None => {
            return Err(crate::error::UpdaterError::NetworkError(
                "All mirrors failed or provided invalid hashes.".to_string(),
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

    info!("Baton Pass: Atomically replacing process image via exec()...");
    use std::os::unix::process::CommandExt;
    let err = Command::new(current_exe).args(&args).exec();

    error!("CRITICAL: self_replace succeeded but exec failed: {}", err);
    Err(crate::error::UpdaterError::SpawnFailed(err.to_string()))
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
        let res = perform_ota_update(dummy_hash, vec![]).await;
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

        let res = perform_ota_update(dummy_hash, vec![mirror_url]).await;

        // It should try the mirror, get the file, hash it, fail verification, and exhaust all mirrors
        if let Err(crate::error::UpdaterError::NetworkError(msg)) = res {
            assert!(msg.contains("failed or provided invalid hashes"));
        } else {
            panic!(
                "Expected NetworkError with invalid hash message, got: {:?}",
                res
            );
        }
    }
}
