use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair,
};
use rustls::ServerConfig;
use time::{Duration, OffsetDateTime};

#[derive(Debug, thiserror::Error)]
pub enum CaError {
    #[error("IO Error: {0}")]
    Io(#[from] std::io::Error),
    #[error("RCGen Error: {0}")]
    Rcgen(#[from] rcgen::Error),
    #[error("Rustls Error: {0}")]
    Rustls(#[from] rustls::Error),
}

pub struct RootCa {
    pub cert_pem: String,
    pub key_pair: KeyPair,
    pub cert: Certificate,
}

pub fn load_or_create_root_ca(config_dir: &Path) -> Result<(RootCa, bool), CaError> {
    let cert_path = config_dir.join("ca_cert.pem");
    let key_path = config_dir.join("ca_key.pem");

    if cert_path.exists() && key_path.exists() {
        let cert_pem = std::fs::read_to_string(&cert_path)?;
        let key_pem = std::fs::read_to_string(&key_path)?;
        let key_pair = KeyPair::from_pem(&key_pem)?;
        let params = CertificateParams::from_ca_cert_pem(&cert_pem)?;
        let cert = params.self_signed(&key_pair)?;
        return Ok((RootCa { cert_pem, key_pair, cert }, false));
    }

    // Generate new CA
    let mut params = CertificateParams::new(vec![])?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "Kinetic Local Root CA");
    dn.push(DnType::OrganizationName, "Kinetic Protocol");
    params.distinguished_name = dn;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.not_before = OffsetDateTime::now_utc();
    params.not_after = OffsetDateTime::now_utc() + Duration::days(730); // 2 years

    let key_pair = KeyPair::generate()?;
    let cert = params.self_signed(&key_pair)?;
    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();

    std::fs::write(&cert_path, &cert_pem)?;
    std::fs::write(&key_path, &key_pem)?;

    #[cfg(unix)]
    std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))?;
    #[cfg(windows)]
    {
        let _ = std::process::Command::new("icacls")
            .args([key_path.to_str().unwrap(), "/inheritance:r", "/grant:r",
                   &format!("{}:F", std::env::var("USERNAME").unwrap_or_default())])
            .status();
    }

    Ok((RootCa { cert_pem, key_pair, cert }, true))
}

pub fn generate_leaf_cert(domain: &str, root_ca: &RootCa) -> Result<ServerConfig, CaError> {
    let mut params = CertificateParams::new(vec![domain.to_string()])?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, domain);
    dn.push(DnType::OrganizationName, "Kinetic Protocol Proxy");
    params.distinguished_name = dn;
    params.not_before = OffsetDateTime::now_utc();
    params.not_after = OffsetDateTime::now_utc() + Duration::days(30);

    let key_pair = KeyPair::generate()?;
    let cert = params.signed_by(&key_pair, &root_ca.cert, &root_ca.key_pair)?;
    
    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();

    // Convert to rustls format
    let mut cert_reader = std::io::BufReader::new(cert_pem.as_bytes());
    let certs: Vec<rustls_pki_types::CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()?;

    let mut root_cert_reader = std::io::BufReader::new(root_ca.cert_pem.as_bytes());
    let root_certs: Vec<rustls_pki_types::CertificateDer<'static>> = rustls_pemfile::certs(&mut root_cert_reader)
        .collect::<Result<Vec<_>, _>>()?;

    let mut full_chain = certs;
    full_chain.extend(root_certs);

    let mut key_reader = std::io::BufReader::new(key_pem.as_bytes());
    let key = rustls_pemfile::private_key(&mut key_reader)?
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "No private key found"))?;

    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(full_chain, key)?;

    Ok(server_config)
}

pub struct LeafCertCache {
    entries: HashMap<String, (Arc<ServerConfig>, Instant)>,
    max_entries: usize,
}

impl LeafCertCache {
    pub fn new() -> Self {
        Self { 
            entries: HashMap::new(),
            max_entries: 256, // reasonable ceiling
        }
    }

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
            let oldest = self.entries.iter()
                .min_by_key(|(_, (_, t))| t)
                .map(|(k, _)| k.clone());
            if let Some(key) = oldest {
                self.entries.remove(&key);
            }
        }

        let config = Arc::new(generate_leaf_cert(domain, root_ca)?);
        self.entries.insert(domain.to_string(), (Arc::clone(&config), now));
        Ok(config)
    }
}
