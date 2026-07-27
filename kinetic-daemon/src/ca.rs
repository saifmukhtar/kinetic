//! Certificate Authority (CA) generation, file locking, leaf certificate signing, and TLS cache management.

use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType, GeneralSubtree,
    IsCa, KeyPair, NameConstraints,
};
use rustls::ServerConfig;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;
use time::{Duration, OffsetDateTime};

/// Defines errors that can occur during Certificate Authority (CA) operations.
#[derive(Debug, thiserror::Error)]
pub enum CaError {
    /// An IO error occurred reading or writing certificates.
    #[error("IO Error: {0}")]
    Io(#[from] std::io::Error),
    /// An error originated from the `rcgen` certificate generator.
    #[error("RCGen Error: {0}")]
    Rcgen(#[from] rcgen::Error),
    /// An error originated from `rustls` configuration.
    #[error("Rustls Error: {0}")]
    Rustls(#[from] rustls::Error),
}

/// Represents a root Certificate Authority (CA) containing the certificate and key pair.
pub struct RootCa {
    /// The generated CA certificate encoded in PEM format.
    pub cert_pem: String,
    /// The private key pair for the CA.
    pub key_pair: KeyPair,
    /// The parsed RCGen CA certificate.
    pub cert: Certificate,
}

/// Loads an existing root CA from the given configuration directory or creates a new one if it doesn't exist.
///
/// # Errors
///
/// Returns a `CaError` if there are IO issues reading/writing the certificate files, or if there is an error
/// generating the root CA certificates.
pub fn load_or_create_root_ca(config_dir: &Path) -> Result<(RootCa, bool), CaError> {
    let network_id = kinetic_core::constants::NETWORK_ID;
    let cert_path = config_dir.join(format!("{}.cert.pem", network_id));
    let key_path = config_dir.join(format!("{}.key.pem", network_id));
    let lock_path = config_dir.join(".ca.lock");

    let mut retries = 0;
    loop {
        // Try to acquire lock
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock_path)
        {
            Ok(_) => break, // Acquired lock!
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                retries += 1;
                if retries > 100 {
                    // Stale lock file, force remove it
                    let _ = std::fs::remove_file(&lock_path);
                } else {
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
            }
            Err(e) => return Err(CaError::Io(e)),
        }
    }

    // Wrap the rest in a closure to ensure we delete the lock file on return/error
    let result = (|| -> Result<(RootCa, bool), CaError> {
        if cert_path.exists() {
            let cert_pem = std::fs::read_to_string(&cert_path)?;

            #[cfg(not(test))]
            let key_pem_opt = keyring::Entry::new("kinetic_daemon", "root_ca_key").and_then(|e| e.get_password());
            #[cfg(test)]
            let key_pem_opt: Result<String, keyring::Error> = Err(keyring::Error::NoEntry);

            let key_pem = match key_pem_opt {
                Ok(k) => k,
                Err(_) if key_path.exists() => std::fs::read_to_string(&key_path)?, // Fallback to disk
                Err(_) => {
                    return Err(CaError::Io(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "CA Private Key missing from both OS Keychain and disk.",
                    )))
                }
            };

            let key_pair = KeyPair::from_pem(&key_pem)?;
            let params = CertificateParams::from_ca_cert_pem(&cert_pem)?;
            let cert = params.self_signed(&key_pair)?;
            return Ok((
                RootCa {
                    cert_pem,
                    key_pair,
                    cert,
                },
                false,
            ));
        }

        // Generate new CA
        let mut params = CertificateParams::new(vec![])?;
        let mut dn = DistinguishedName::new();
        dn.push(
            DnType::CommonName,
            format!("{} Local Root CA", kinetic_core::constants::NETWORK_ID),
        );
        dn.push(
            DnType::OrganizationName,
            format!("{} Protocol", kinetic_core::constants::NETWORK_ID),
        );
        params.distinguished_name = dn;
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.name_constraints = Some(NameConstraints {
            permitted_subtrees: vec![
                GeneralSubtree::DnsName("kin".to_string()),
                GeneralSubtree::DnsName(kinetic_core::constants::TLD_SUFFIX.to_string()),
            ],
            excluded_subtrees: vec![],
        });
        params.not_before = OffsetDateTime::now_utc();
        params.not_after = OffsetDateTime::now_utc() + Duration::days(730); // 2 years

        let key_pair = KeyPair::generate()?;
        let cert = params.self_signed(&key_pair)?;
        let cert_pem = cert.pem();
        let key_pem = key_pair.serialize_pem();

        std::fs::write(&cert_path, &cert_pem)?;

        #[cfg(not(test))]
        let keyring_success = {
            let entry = keyring::Entry::new("kinetic_daemon", "root_ca_key");
            match entry {
                Ok(e) => e.set_password(&key_pem).is_ok(),
                Err(_) => false,
            }
        };
        #[cfg(test)]
        let keyring_success = false;

        if keyring_success {
            tracing::info!("Root CA private key securely stored in OS Keychain.");
            let _ = std::fs::remove_file(&key_path);
        } else {
            tracing::warn!(
                "Failed to store Root CA key in OS Keychain. Falling back to disk storage."
            );

            #[cfg(unix)]
            {
                use std::io::Write;
                use std::os::unix::fs::OpenOptionsExt;
                let mut f = std::fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .mode(0o600)
                    .open(&key_path)?;
                f.write_all(key_pem.as_bytes())?;
            }
            #[cfg(not(unix))]
            {
                std::fs::write(&key_path, &key_pem)?;
            }
            #[cfg(windows)]
            {
                let _ = std::process::Command::new("icacls")
                    .args([
                        key_path.to_str().unwrap_or_default(),
                        "/inheritance:r",
                        "/grant:r",
                        &format!("{}:F", std::env::var("USERNAME").unwrap_or_default()),
                    ])
                    .status();
            }
        }

        // Attempt to trust the newly generated CA locally.
        // We do not fail the overall initialization if this fails, as users may reject the prompt.
        trust_root_ca(&cert_path);

        Ok((
            RootCa {
                cert_pem,
                key_pair,
                cert,
            },
            true,
        ))
    })();

    let _ = std::fs::remove_file(&lock_path);
    result
}

/// Attempts to inject the provided Root CA certificate into the OS-level trust store.
///
/// This invokes native GUI permission dialogs (Windows UAC, macOS Touch ID/Password,
/// or Linux Polkit) so the user can authorize the installation of the CA.
///
/// If the command fails or the user rejects the prompt, we log a warning but do not panic.
#[cfg(not(test))]
fn trust_root_ca(cert_path: &Path) {
    #[cfg(windows)]
    {
        tracing::info!("Prompting Windows user to trust the Kinetic Root CA...");
        let status = std::process::Command::new("certutil")
            .args([
                "-addstore",
                "-user",
                "root",
                cert_path.to_str().unwrap_or_default(),
            ])
            .status();

        match status {
            Ok(s) if s.success() => tracing::info!("Successfully trusted Root CA on Windows."),
            _ => tracing::warn!("Failed or rejected Root CA trust installation on Windows."),
        }
    }

    #[cfg(target_os = "macos")]
    {
        tracing::info!("Prompting macOS user to trust the Kinetic Root CA...");
        let script = format!(
            "do shell script \"security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain {}\" with administrator privileges",
            cert_path.display()
        );
        let status = std::process::Command::new("osascript")
            .args(["-e", &script])
            .status();

        match status {
            Ok(s) if s.success() => tracing::info!("Successfully trusted Root CA on macOS."),
            _ => tracing::warn!("Failed or rejected Root CA trust installation on macOS."),
        }
    }

    #[cfg(target_os = "linux")]
    {
        tracing::info!("Prompting Linux user (via pkexec) to trust the Kinetic Root CA...");
        // This targets Debian/Ubuntu style CA stores. Arch/Fedora use different paths,
        // but this covers the most common desktop setups (e.g. Ubuntu).
        let cmd = format!(
            "cp {} /usr/local/share/ca-certificates/kinetic.crt && update-ca-certificates",
            cert_path.display()
        );
        let status = std::process::Command::new("pkexec")
            .args(["sh", "-c", &cmd])
            .status();

        match status {
            Ok(s) if s.success() => tracing::info!("Successfully trusted Root CA on Linux."),
            _ => tracing::warn!("Failed or rejected Root CA trust installation on Linux."),
        }
    }
}

#[cfg(test)]
fn trust_root_ca(_cert_path: &Path) {}

/// Generates a leaf certificate for a specific domain, signed by the given root CA.
///
/// # Errors
///
/// Returns a `CaError` if there are issues generating the certificate, serializing it, or building the `ServerConfig`.
pub fn generate_leaf_cert(domain: &str, root_ca: &RootCa) -> Result<ServerConfig, CaError> {
    let mut params = CertificateParams::new(vec![domain.to_string()])?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, domain);
    dn.push(
        DnType::OrganizationName,
        format!("{} Protocol Proxy", kinetic_core::constants::NETWORK_ID),
    );
    params.distinguished_name = dn;
    params.not_before = OffsetDateTime::now_utc();
    params.not_after = OffsetDateTime::now_utc() + Duration::days(30);

    let key_pair = KeyPair::generate()?;
    let cert = params.signed_by(&key_pair, &root_ca.cert, &root_ca.key_pair)?;

    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();

    // Convert to rustls format
    let mut cert_reader = std::io::BufReader::new(cert_pem.as_bytes());
    let certs: Vec<rustls_pki_types::CertificateDer<'static>> =
        rustls_pemfile::certs(&mut cert_reader).collect::<Result<Vec<_>, _>>()?;

    let mut root_cert_reader = std::io::BufReader::new(root_ca.cert_pem.as_bytes());
    let root_certs: Vec<rustls_pki_types::CertificateDer<'static>> =
        rustls_pemfile::certs(&mut root_cert_reader).collect::<Result<Vec<_>, _>>()?;

    let mut full_chain = certs;
    full_chain.extend(root_certs);

    let mut key_reader = std::io::BufReader::new(key_pem.as_bytes());
    let key = rustls_pemfile::private_key(&mut key_reader)?.ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "No private key found")
    })?;

    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(full_chain, key)?;

    Ok(server_config)
}

/// A cache for leaf certificates to avoid frequent generation and reduce overhead.
pub struct LeafCertCache {
    pub(crate) entries: HashMap<String, (Arc<ServerConfig>, Instant)>,
    pub(crate) max_entries: usize,
}

impl Default for LeafCertCache {
    fn default() -> Self {
        Self::new()
    }
}

impl LeafCertCache {
    /// Creates a new `LeafCertCache` with a default maximum capacity.
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            max_entries: 256, // reasonable ceiling
        }
    }

    /// Retrieves a cached server configuration for the domain, or creates a new one if missing or expired.
    ///
    /// # Errors
    ///
    /// Returns a `CaError` if generating a new leaf certificate fails.
    pub fn get_or_create(
        &mut self,
        domain: &str,
        root_ca: &RootCa,
    ) -> Result<Arc<ServerConfig>, CaError> {
        let now = Instant::now();

        if let Some((config, created)) = self.entries.get(domain) {
            if now.duration_since(*created) < std::time::Duration::from_secs(3600) {
                return Ok(Arc::clone(config));
            }
        }

        // Evict if at capacity before inserting
        if self.entries.len() >= self.max_entries {
            // Remove oldest entry
            let oldest = self
                .entries
                .iter()
                .min_by_key(|(_, (_, t))| t)
                .map(|(k, _)| k.clone());
            if let Some(key) = oldest {
                self.entries.remove(&key);
            }
        }

        let config = Arc::new(generate_leaf_cert(domain, root_ca)?);
        self.entries
            .insert(domain.to_string(), (Arc::clone(&config), now));
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::{load_or_create_root_ca, LeafCertCache};
    use tempfile::tempdir;

    #[test]
    fn test_leaf_cert_cache_eviction() {
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();
        let dir = tempdir().unwrap();
        let (root_ca, _) = load_or_create_root_ca(dir.path()).unwrap();

        let mut cache = LeafCertCache::new();
        cache.max_entries = 5;

        for i in 0..10 {
            let domain = format!("test{}.kin", i);
            cache.get_or_create(&domain, &root_ca).unwrap();
        }

        // Assert cache size is max 5
        assert_eq!(cache.entries.len(), 5);
        // Ensure newest domains are in the cache
        assert!(cache.entries.contains_key("test9.kin"));
    }

    #[test]
    fn test_ca_lock_file_stale_recovery() {
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();
        let dir = tempdir().unwrap();
        let lock_path = dir.path().join(".ca.lock");

        // Create a stale lock file
        std::fs::write(&lock_path, "").unwrap();

        // Should recover and delete the lock
        let _ = load_or_create_root_ca(dir.path()).unwrap();
        assert!(!lock_path.exists());
    }

    #[test]
    fn test_load_existing_root_ca() {
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();
        let dir = tempdir().unwrap();

        // First call should generate
        let (root_ca_1, generated) = load_or_create_root_ca(dir.path()).unwrap();
        assert!(generated);

        // Second call should load
        let (root_ca_2, generated_again) = load_or_create_root_ca(dir.path()).unwrap();
        assert!(!generated_again);

        assert_eq!(root_ca_1.cert_pem, root_ca_2.cert_pem);
    }

    #[test]
    fn test_generate_leaf_cert() {
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();
        let dir = tempdir().unwrap();
        let (root_ca, _) = load_or_create_root_ca(dir.path()).unwrap();

        let _config = super::generate_leaf_cert("testdomain.kin", &root_ca).unwrap();
        // If it returns Ok, the generation and rustls struct conversion succeeded.
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;
    use tempfile::tempdir;

    proptest! {
        #[test]
        fn test_fuzz_leaf_cert_generation(
            // Generate chaotic domains, up to 255 chars, including valid and invalid DNS chars
            domain in "[a-zA-Z0-9.-]{1,255}"
        ) {
            rustls::crypto::ring::default_provider().install_default().ok();
            let dir = tempdir().unwrap();
            let (root_ca, _) = load_or_create_root_ca(dir.path()).unwrap();

            // Should either succeed or safely return an Rcgen error, but NEVER panic
            let result = generate_leaf_cert(&domain, &root_ca);

            match result {
                Ok(_) => prop_assert!(true),
                Err(CaError::Rcgen(_)) => prop_assert!(true), // Invalid DNS chars hit rcgen parsing error safely
                Err(e) => prop_assert!(false, "Unexpected error type: {:?}", e),
            }
        }
    }
}
