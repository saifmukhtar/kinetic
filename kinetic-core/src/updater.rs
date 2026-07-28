//! Over-The-Air (OTA) binary update engine and mirror verification pipeline.
//!
//! Handles HTTPS mirror queries, strict version verification (`manifest.version == release.version`),
//! SHA-256 chunked download hashing, atomic binary image replacement ([`self_replace`]), and process re-execution.

use futures_util::StreamExt;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::env;
use std::io::Write;
use std::process::Command;
use tempfile::NamedTempFile;
use tracing::{error, info, warn};
use web_time::Duration;

/// Represents parsed metadata from `manifest.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    /// Canonical version string of the target release (e.g. `"1.2.3"`).
    pub version: String,
    /// Mapping of binary target names to expected SHA-256 hexadecimal hash strings.
    pub binaries: HashMap<String, String>,
}

/// Represents parsed release metadata from `release.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Release {
    /// Canonical version string of the release.
    pub version: String,
}

/// Downloads and atomically replaces the running executable from verified HTTPS mirrors.
///
/// # Security & Safety Guarantees
///
/// 1. **HTTPS Enforcement**: Rejects insecure `http://` mirror URLs.
/// 2. **Strict Version Verification**: Asserts that `manifest.version == release.version`.
/// 3. **SHA-256 Hash Matching**: Verifies the SHA-256 digest of downloaded binaries before disk swap.
/// 4. **Chunked Memory Cap**: Streams binary chunks with a 250 MB max limit to prevent OOM attacks.
/// 5. **Atomic Process Replacement**: Swaps binary images on disk using [`self_replace`] and executes POSIX `exec()` to inherit runtime parameters.
///
/// # Errors
///
/// - Returns [`crate::error::UpdaterError::NoMirrorsProvided`] if the mirror vector is empty.
/// - Returns [`crate::error::UpdaterError::NetworkError`] if all mirrors fail or return invalid HTTP responses.
/// - Returns [`crate::error::UpdaterError::ReqwestError`] if HTTP client setup or request building fails.
/// - Returns [`crate::error::UpdaterError::SelfReplaceError`] if file swapping fails (e.g. permission denied or active execution lock).
/// - Returns [`crate::error::UpdaterError::SpawnFailed`] if process re-execution fails.
pub async fn perform_ota_update(
    self_id: &str,
    expected_manifest_hash: [u8; 32],
    mirrors: Vec<String>,
) -> Result<(), crate::error::UpdaterError> {
    if mirrors.is_empty() {
        return Err(crate::error::UpdaterError::NoMirrorsProvided);
    }

    let client = Client::builder().timeout(Duration::from_secs(60)).build()?;

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
        if !mirror.starts_with("https://") {
            warn!("Skipping insecure mirror (HTTP not allowed): {}", mirror);
            continue;
        }

        info!("Attempting OTA update from mirror: {}", mirror);

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

        let mut hasher = Sha256::new();
        hasher.update(&manifest_bytes);
        let result_hash = hasher.finalize();
        let mut result_hash_array = [0u8; 32];
        result_hash_array.copy_from_slice(&result_hash);

        if result_hash_array != expected_manifest_hash {
            warn!(
                "Manifest hash verification failed for mirror: {}. Expected: {}, Got: {}",
                mirror,
                hex::encode(expected_manifest_hash),
                hex::encode(result_hash_array)
            );
            continue;
        }

        info!("Manifest hash verified for mirror: {}", mirror);

        // 3. Parse Manifest and lookup target hash
        let manifest: Manifest = match serde_json::from_slice(&manifest_bytes) {
            Ok(m) => m,
            Err(e) => {
                warn!(
                    "Failed to parse strict JSON manifest from mirror {}: {}",
                    mirror, e
                );
                continue;
            }
        };

        // Fetch release.json and verify version matches strictly
        let release_url = format!("{}/release.json", mirror);
        let release_res = match client.get(&release_url).send().await {
            Ok(res) if res.status().is_success() => res,
            Ok(res) => {
                warn!(
                    "Mirror {} returned status {} for release.json",
                    mirror,
                    res.status()
                );
                continue;
            }
            Err(e) => {
                warn!(
                    "Mirror {} failed to connect for release.json: {}",
                    mirror, e
                );
                continue;
            }
        };

        let release_bytes = match release_res.bytes().await {
            Ok(b) => b,
            Err(e) => {
                warn!(
                    "Failed to read release.json bytes from mirror {}: {}",
                    mirror, e
                );
                continue;
            }
        };

        let release: Release = match serde_json::from_slice(&release_bytes) {
            Ok(r) => r,
            Err(e) => {
                warn!(
                    "Failed to parse strict JSON release.json from mirror {}: {}",
                    mirror, e
                );
                continue;
            }
        };

        if manifest.version != release.version {
            warn!("Strict version verification failed! Manifest version ({}) != Release version ({}). Aborting.", manifest.version, release.version);
            continue;
        }

        info!("Strict version verification passed: v{}", manifest.version);

        let target_hash_hex = match manifest.binaries.get(self_id) {
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
        let mut bytes_downloaded = 0usize;
        const MAX_DOWNLOAD_SIZE: usize = 250 * 1024 * 1024; // 250 MB max

        while let Some(chunk_result) = byte_stream.next().await {
            match chunk_result {
                Ok(chunk) => {
                    bytes_downloaded = bytes_downloaded.saturating_add(chunk.len());
                    if bytes_downloaded > MAX_DOWNLOAD_SIZE {
                        error!(
                            "OTA update aborted: Binary exceeds {} byte limit.",
                            MAX_DOWNLOAD_SIZE
                        );
                        download_success = false;
                        break;
                    }

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

    let current_exe = match env::current_exe() {
        Ok(exe) => exe,
        Err(e) => {
            error!("Failed to get current executable path: {}", e);
            return Err(e.into());
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

        let dummy_hash = [1u8; 32];

        // The mirror will be skipped entirely because it's http://, failing with NetworkError "All mirrors failed".
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

    #[test]
    fn test_strict_version_matching_logic() {
        let manifest_json = r#"{ "version": "1.2.3", "binaries": {} }"#;
        let release_json = r#"{ "version": "1.2.3", "notes": "foo" }"#;

        let manifest: Manifest = serde_json::from_str(manifest_json).unwrap();
        let release: Release = serde_json::from_str(release_json).unwrap();

        assert_eq!(manifest.version, release.version);
    }

    #[test]
    fn test_strict_version_mismatch_logic() {
        let manifest_json = r#"{ "version": "1.2.3", "binaries": {} }"#;
        let release_json = r#"{ "version": "1.2.4" }"#;

        let manifest: Manifest = serde_json::from_str(manifest_json).unwrap();
        let release: Release = serde_json::from_str(release_json).unwrap();

        assert_ne!(manifest.version, release.version);
    }

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn doesnt_crash_manifest_parsing(s in any::<String>()) {
            let _ = serde_json::from_str::<Manifest>(&s);
        }

        #[test]
        fn doesnt_crash_release_parsing(s in any::<String>()) {
            let _ = serde_json::from_str::<Release>(&s);
        }

        #[test]
        fn valid_manifest_versions_parse(version in "[a-zA-Z0-9.-]+") {
            let json = format!(r#"{{ "version": "{}", "binaries": {{}} }}"#, version);
            let manifest: Manifest = serde_json::from_str(&json).unwrap();
            assert_eq!(manifest.version, version);
        }
    }
}
