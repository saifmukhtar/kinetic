use axum::{routing::get, Router};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::path::PathBuf;
use tracing::{error, info, warn};

pub mod os;
pub use os::*;

#[derive(Debug, thiserror::Error)]
pub enum ProxyConfigError {
    #[error("IO Error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serialization Error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("Command failed: {0}")]
    Command(String),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SavedState {
    pub previous_pac_url: Option<String>,
    pub proxy_type: Option<String>,
    pub macos_services: Option<std::collections::HashMap<String, String>>,
}

pub trait ProxyConfigurator: Send + Sync {
    fn install(&self, pac_url: &str) -> Result<(), ProxyConfigError>;
    fn uninstall(&self) -> Result<(), ProxyConfigError>;
    fn save_previous_state(&self) -> Result<SavedState, ProxyConfigError>;
    fn restore_state(&self, state: &SavedState) -> Result<(), ProxyConfigError>;
}

pub struct FallbackConfigurator;
impl ProxyConfigurator for FallbackConfigurator {
    fn install(&self, pac_url: &str) -> Result<(), ProxyConfigError> {
        warn!("No automatic OS proxy configurator available for this environment.");
        warn!("Please manually set your browser or system proxy autoconfiguration URL to: {}", pac_url);
        Ok(())
    }
    fn uninstall(&self) -> Result<(), ProxyConfigError> { Ok(()) }
    fn save_previous_state(&self) -> Result<SavedState, ProxyConfigError> {
        Ok(SavedState { previous_pac_url: None, proxy_type: None, macos_services: None })
    }
    fn restore_state(&self, _state: &SavedState) -> Result<(), ProxyConfigError> { Ok(()) }
}

pub fn detect_configurator() -> Box<dyn ProxyConfigurator> {
    match std::env::consts::OS {
        "linux" => detect_linux_configurator(),
        "macos" | "darwin" => {
            #[cfg(target_os = "macos")]
            return Box::new(MacosConfigurator);
            #[cfg(not(target_os = "macos"))]
            return Box::new(FallbackConfigurator);
        }
        "windows" => {
            #[cfg(target_os = "windows")]
            return Box::new(WindowsConfigurator);
            #[cfg(not(target_os = "windows"))]
            return Box::new(FallbackConfigurator);
        }
        _ => Box::new(FallbackConfigurator),
    }
}

pub struct PacManager {
    configurator: Box<dyn ProxyConfigurator>,
    lock_path: PathBuf,
}

impl PacManager {
    pub fn new(config_dir: &std::path::Path) -> Self {
        Self {
            configurator: detect_configurator(),
            lock_path: config_dir.join("proxy_active.lock"),
        }
    }

    pub fn install(&self, pac_url: &str) -> Result<(), ProxyConfigError> {
        if self.lock_path.exists() {
            if let Ok(Ok(saved)) = File::open(&self.lock_path).map(serde_json::from_reader::<_, SavedState>) {
                let _ = self.configurator.restore_state(&saved);
            }
        }
        let previous = self.configurator.save_previous_state()?;
        let tmp_path = self.lock_path.with_extension("tmp");
        if let Ok(file) = File::create(&tmp_path) {
            let _ = serde_json::to_writer(file, &previous);
            let _ = std::fs::rename(&tmp_path, &self.lock_path);
        }
        self.configurator.install(pac_url)?;
        info!("Successfully installed PAC file OS routing to {}", pac_url);
        Ok(())
    }

    pub fn uninstall(&self) -> Result<(), ProxyConfigError> {
        if self.lock_path.exists() {
            if let Ok(Ok(saved)) = File::open(&self.lock_path).map(serde_json::from_reader::<_, SavedState>) {
                let _ = self.configurator.restore_state(&saved);
            } else {
                let _ = self.configurator.uninstall();
            }
            let _ = std::fs::remove_file(&self.lock_path);
            info!("Successfully restored original OS proxy settings");
        } else {
            let _ = self.configurator.uninstall();
        }
        Ok(())
    }
}

#[derive(Deserialize, Debug)]
struct RegisteredProxy {
    tld: String,
    proxy_port: u16,
    #[serde(default = "default_ip")]
    proxy_ip: String,
}

fn default_ip() -> String {
    "127.0.0.1".to_string()
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let base_dir = dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("kinetic_global");
    
    std::fs::create_dir_all(&base_dir)?;
    
    let proxies_dir = base_dir.join("proxies");
    std::fs::create_dir_all(&proxies_dir)?;

    let pac_manager = PacManager::new(&base_dir);
    
    let pac_url = "http://127.0.0.1:16001/proxy.pac";
    pac_manager.install(pac_url)?;

    let app = Router::new().route(
        "/proxy.pac",
        get(move |headers: axum::http::HeaderMap| async move {
            let host = headers
                .get(axum::http::header::HOST)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            let host_only = host.split(':').next().unwrap_or("");
            
            if host_only == "localhost"
                || host_only == "127.0.0.1"
                || host_only == "[::1]"
            {
                let mut pac_script = String::from("function FindProxyForURL(url, host) {\n");
                
                let mut proxy_map: std::collections::HashMap<String, RegisteredProxy> = std::collections::HashMap::new();
                let mut is_atlas_map: std::collections::HashMap<String, bool> = std::collections::HashMap::new();

                // Scan proxies dir for JSON files
                if let Ok(entries) = std::fs::read_dir(&proxies_dir) {
                    for entry in entries.flatten() {
                        if let Some(ext) = entry.path().extension() {
                            if ext == "json" {
                                if let Ok(file) = File::open(entry.path()) {
                                    if let Ok(proxy_info) = serde_json::from_reader::<_, RegisteredProxy>(file) {
                                        let tld = if proxy_info.tld.starts_with('.') { proxy_info.tld.clone() } else { format!(".{}", proxy_info.tld) };
                                        
                                        let is_atlas = entry.file_name().to_string_lossy().starts_with("atlas_");

                                        // Conflict resolution: Native daemons ALWAYS override Atlas proxies
                                        let should_insert = match is_atlas_map.get(&tld) {
                                            Some(true) if !is_atlas => true, // Replace Atlas with Native
                                            Some(false) if is_atlas => false, // Ignore Atlas if Native exists
                                            Some(_) => false, // First come first serve for same types
                                            None => true,
                                        };

                                        if should_insert {
                                            is_atlas_map.insert(tld.clone(), is_atlas);
                                            proxy_map.insert(tld, proxy_info);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                for (tld, proxy_info) in proxy_map {
                    // Use proxy_ip for IPv4 and fallback to loopback for IPv6
                    let ipv6 = if proxy_info.proxy_ip == "127.0.0.1" { "[::1]" } else { &proxy_info.proxy_ip };
                    
                    pac_script.push_str(&format!(
                        "    if (shExpMatch(host, \"*{}\")) return \"PROXY {}:{}; PROXY {}:{}; DIRECT\";\n",
                        tld, proxy_info.proxy_ip, proxy_info.proxy_port, ipv6, proxy_info.proxy_port
                    ));
                    pac_script.push_str(&format!(
                        "    if (shExpMatch(host, \"*{}.\")) return \"PROXY {}:{}; PROXY {}:{}; DIRECT\";\n",
                        tld, proxy_info.proxy_ip, proxy_info.proxy_port, ipv6, proxy_info.proxy_port
                    ));
                }

                pac_script.push_str("    return \"DIRECT\";\n}\n");

                axum::response::Response::builder()
                    .header("Content-Type", "application/x-ns-proxy-autoconfig")
                    .body(pac_script)
                    .unwrap_or_default()
            } else {
                axum::response::Response::builder()
                    .status(403)
                    .body("Forbidden".to_string())
                    .unwrap_or_default()
            }
        }),
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:16001").await?;
    info!("kinetic-pac background service running at http://127.0.0.1:16001");
    
    // Install signal handlers to gracefully uninstall PAC
    tokio::spawn(async move {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).unwrap();
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = sigterm.recv() => {}
        }
        info!("kinetic-pac shutting down, restoring OS proxy settings...");
        let _ = pac_manager.uninstall();
        std::process::exit(0);
    });

    axum::serve(listener, app).await?;
    Ok(())
}
