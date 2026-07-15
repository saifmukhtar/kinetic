use axum::{routing::get, Router};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::net::SocketAddr;
use std::path::PathBuf;
use tracing::{error, info, warn};

pub mod os;

pub use os::*;
/// Errors that can occur when configuring the operating system proxy settings.
#[derive(Debug, thiserror::Error)]
pub enum ProxyConfigError {
    #[error("IO Error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serialization Error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("Command failed: {0}")]
    Command(String),
}

/// Represents the saved state of the OS proxy settings prior to modification,
/// used to cleanly restore settings on shutdown.
#[derive(Debug, Serialize, Deserialize)]
pub struct SavedState {
    pub previous_pac_url: Option<String>,
    pub proxy_type: Option<String>,
}

/// Defines the interface for an OS-specific proxy configuration manager.
pub trait ProxyConfigurator: Send + Sync {
    fn install(&self, pac_url: &str) -> Result<(), ProxyConfigError>;
    fn uninstall(&self) -> Result<(), ProxyConfigError>;
    fn save_previous_state(&self) -> Result<SavedState, ProxyConfigError>;
    fn restore_state(&self, state: &SavedState) -> Result<(), ProxyConfigError>;
}

/// A fallback configurator used when the current OS or desktop environment is unsupported.
/// Logs instructions for manual proxy setup instead of altering system settings.
pub struct FallbackConfigurator;

impl ProxyConfigurator for FallbackConfigurator {
    fn install(&self, pac_url: &str) -> Result<(), ProxyConfigError> {
        warn!("No automatic OS proxy configurator available for this environment.");
        warn!(
            "Please manually set your browser or system proxy autoconfiguration URL to: {}",
            pac_url
        );
        Ok(())
    }

    fn uninstall(&self) -> Result<(), ProxyConfigError> {
        Ok(())
    }

    fn save_previous_state(&self) -> Result<SavedState, ProxyConfigError> {
        Ok(SavedState {
            previous_pac_url: None,
            proxy_type: None,
        })
    }

    fn restore_state(&self, _state: &SavedState) -> Result<(), ProxyConfigError> {
        Ok(())
    }
}

/// Detects and returns the appropriate `ProxyConfigurator` for the current operating system
/// and desktop environment.
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
        _ => {
            warn!("Unsupported OS for automatic proxy configuration. Using fallback.");
            Box::new(FallbackConfigurator)
        }
    }
}

/// Manages the installation and uninstallation of the Proxy Auto-Configuration (PAC) file
/// into the system settings, ensuring clean recovery across restarts.
pub struct PacManager {
    configurator: Box<dyn ProxyConfigurator>,
    lock_path: PathBuf,
}

impl PacManager {
    /// Creates a new `PacManager`, initializing the OS configurator and defining the lockfile path.
    pub fn new(config_dir: &std::path::Path) -> Self {
        Self {
            configurator: detect_configurator(),
            lock_path: config_dir.join("proxy_active.lock"),
        }
    }

    /// Installs the PAC URL into the system proxy settings.
    /// Safely saves the previous state to a lockfile for recovery.
    ///
    /// # Errors
    ///
    /// Returns a `ProxyConfigError` if saving the state or installing the PAC URL fails.
    pub fn install(&self, pac_url: &str) -> Result<(), ProxyConfigError> {
        // Handle unclean shutdown recovery
        if self.lock_path.exists() {
            match File::open(&self.lock_path).map(serde_json::from_reader::<_, SavedState>) {
                Ok(Ok(saved)) => {
                    let _ = self.configurator.restore_state(&saved);
                    warn!("Detected unclean shutdown — proxy settings restored from lockfile");
                }
                _ => {
                    warn!("Corrupt lockfile detected — skipping restore, deleting");
                    let _ = std::fs::remove_file(&self.lock_path);
                }
            }
        }

        // Save current state atomically
        let previous = self.configurator.save_previous_state()?;
        let tmp_path = self.lock_path.with_extension("tmp");
        if let Ok(file) = File::create(&tmp_path) {
            let _ = serde_json::to_writer(file, &previous);
            let _ = std::fs::rename(&tmp_path, &self.lock_path);
        }

        // Install new PAC
        self.configurator.install(pac_url)?;
        info!("Successfully installed PAC file OS routing to {}", pac_url);

        Ok(())
    }

    /// Restores the system proxy settings to their state prior to installation, using the lockfile.
    ///
    /// # Errors
    ///
    /// Returns a `ProxyConfigError` if uninstallation or restoration commands fail.
    pub fn uninstall(&self) -> Result<(), ProxyConfigError> {
        if self.lock_path.exists() {
            match File::open(&self.lock_path).map(serde_json::from_reader::<_, SavedState>) {
                Ok(Ok(saved)) => {
                    let _ = self.configurator.restore_state(&saved);
                }
                _ => {
                    let _ = self.configurator.uninstall();
                }
            }
            let _ = std::fs::remove_file(&self.lock_path);
            info!("Successfully restored original OS proxy settings");
        } else {
            let _ = self.configurator.uninstall();
        }

        Ok(())
    }
}

/// Starts a local HTTP server to host the `proxy.pac` file.
///
/// # Errors
///
/// Returns an error if the server fails to bind to the specified port.
pub async fn start_pac_server(port: u16, proxy_port: u16) -> anyhow::Result<()> {
    let pac_script = format!(
        r#"
function FindProxyForURL(url, host) {{
    if (shExpMatch(host, "*.kin")) return "PROXY 127.0.0.1:{0}; PROXY [::1]:{0}; DIRECT";
    if (shExpMatch(host, "*.kin.")) return "PROXY 127.0.0.1:{0}; PROXY [::1]:{0}; DIRECT";
    return "DIRECT";
}}"#,
        proxy_port
    )
    .trim()
    .to_string();

    let app = Router::new().route(
        "/proxy.pac",
        get(move |headers: axum::http::HeaderMap| async move {
            let host = headers
                .get(axum::http::header::HOST)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            if host.starts_with("localhost")
                || host.starts_with("127.0.0.1")
                || host.starts_with("[::1]")
            {
                axum::response::Response::builder()
                    .header("Content-Type", "application/x-ns-proxy-autoconfig")
                    .body(pac_script.clone())
                    .unwrap_or_default()
            } else {
                axum::response::Response::builder()
                    .status(403)
                    .body("Forbidden".to_string())
                    .unwrap_or_default()
            }
        }),
    );

    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let mut listener = None;
    for _ in 0..10 {
        if let Ok(l) = tokio::net::TcpListener::bind(addr).await {
            listener = Some(l);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    let listener = listener.ok_or_else(|| anyhow::anyhow!("Failed to bind to {}", addr))?;
    info!("Serving proxy.pac on http://{}/proxy.pac", addr);

    tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            error!("PAC server error: {}", e);
        }
    });

    Ok(())
}
