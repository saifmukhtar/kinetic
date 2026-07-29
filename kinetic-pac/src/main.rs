//! Local server and configurator for routing `.kin` domains using Proxy Auto-Configuration (PAC).
//!
//! This daemon provides an HTTP endpoint serving a dynamically updated `proxy.pac` script.
//! It seamlessly integrates with OS-level proxy settings on Windows, macOS, and Linux,
//! routing requests for `.kin` and other configured domains to the Kinetic HTTP proxy,
//! while allowing normal internet traffic to bypass the proxy.

use axum::{routing::get, Router};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::path::PathBuf;
use tracing::{info, warn};

pub mod error;
pub use error::*;

pub mod os;
pub use os::*;

/// Represents the preserved, original OS proxy settings before Kinetic modified them.
///
/// This state is serialized to a lock file on disk (`proxy_active.lock`) so that if the
/// daemon crashes or is forcefully terminated, the exact original proxy settings can be
/// seamlessly restored on the next run.
#[derive(Debug, Serialize, Deserialize)]
pub struct SavedState {
    /// The previous PAC configuration URL, if one existed.
    pub previous_pac_url: Option<String>,
    /// The previous proxy mode/type (e.g., GNOME/KDE proxy modes).
    pub proxy_type: Option<String>,
    /// macOS specific: mapping of network service names to their previous PAC URLs.
    pub macos_services: Option<std::collections::HashMap<String, String>>,
}

/// Core interface for mutating OS-level network proxy settings.
///
/// Each supported OS provides a struct that implements this trait, abstracting away
/// platform-specific commands (like `gsettings`, `networksetup`, or Registry edits).
pub trait ProxyConfigurator: Send + Sync {
    /// Applies the given PAC URL as the system-wide automatic proxy configuration.
    ///
    /// # Errors
    /// Returns a [`PacError`] if the underlying OS command fails or lacks permissions.
    fn install(&self, pac_url: &str) -> Result<(), PacError>;

    /// Strips the Kinetic PAC URL and disables automatic proxy configuration.
    ///
    /// # Errors
    /// Returns a [`PacError`] if the underlying OS command fails.
    fn uninstall(&self) -> Result<(), PacError>;

    /// Captures the current OS proxy configuration into a structured snapshot.
    ///
    /// # Errors
    /// Returns a [`PacError`] if it fails to read the current proxy state.
    fn save_previous_state(&self) -> Result<SavedState, PacError>;

    /// Restores the OS proxy configuration from a previously saved snapshot.
    ///
    /// # Errors
    /// Returns a [`PacError`] if the underlying OS command fails to apply the old state.
    fn restore_state(&self, state: &SavedState) -> Result<(), PacError>;
}

/// Fallback proxy configurator for unsupported environments.
///
/// Does not mutate any OS settings; instead, it outputs warnings prompting the user
/// to manually configure their proxy.
pub struct FallbackConfigurator;

impl ProxyConfigurator for FallbackConfigurator {
    fn install(&self, pac_url: &str) -> Result<(), PacError> {
        warn!("No automatic OS proxy configurator available for this environment.");
        warn!(
            "Please manually set your browser or system proxy autoconfiguration URL to: {}",
            pac_url
        );
        Ok(())
    }
    fn uninstall(&self) -> Result<(), PacError> {
        Ok(())
    }
    fn save_previous_state(&self) -> Result<SavedState, PacError> {
        Ok(SavedState {
            previous_pac_url: None,
            proxy_type: None,
            macos_services: None,
        })
    }
    fn restore_state(&self, _state: &SavedState) -> Result<(), PacError> {
        Ok(())
    }
}

/// Automatically detects the host operating system (and desktop environment) and
/// returns the optimal [`ProxyConfigurator`] implementation.
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

/// Manages the lifecycle of PAC OS integration, including state lockfiles.
pub struct PacManager {
    configurator: Box<dyn ProxyConfigurator>,
    lock_path: PathBuf,
}

impl PacManager {
    /// Constructs a new `PacManager` storing its lockfile in `config_dir`.
    pub fn new(config_dir: &std::path::Path) -> Self {
        Self {
            configurator: detect_configurator(),
            lock_path: config_dir.join("proxy_active.lock"),
        }
    }

    /// Backs up current OS proxy settings, locks the state, and installs the new PAC URL.
    ///
    /// # Errors
    /// Returns a [`PacError`] if IO fails on the lockfile or the OS rejects the configuration.
    pub fn install(&self, pac_url: &str) -> Result<(), PacError> {
        if self.lock_path.exists() {
            if let Ok(Ok(saved)) =
                File::open(&self.lock_path).map(serde_json::from_reader::<_, SavedState>)
            {
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

    /// Restores the OS proxy settings using the backup in the lockfile and cleans up.
    ///
    /// # Errors
    /// Returns a [`PacError`] if the OS commands to uninstall the proxy configuration fail.
    pub fn uninstall(&self) -> Result<(), PacError> {
        if self.lock_path.exists() {
            if let Ok(Ok(saved)) =
                File::open(&self.lock_path).map(serde_json::from_reader::<_, SavedState>)
            {
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

/// Represents a serialized proxy backend registered by other Kinetic components.
#[derive(Deserialize, Debug)]
struct RegisteredProxy {
    tld: String,
    proxy_port: u16,
    #[serde(default = "default_ip")]
    proxy_ip: String,
}

/// Default proxy IP (localhost) if none is provided in the JSON registry.
fn default_ip() -> String {
    "127.0.0.1".to_string()
}

/// Starts the Kinetic PAC daemon.
///
/// Discovers configured proxies, runs an HTTP server hosting the dynamic `proxy.pac` script,
/// and applies the routing script to the host operating system.
///
/// # Errors
/// Returns an `anyhow::Result` error if directory creation or the HTTP socket bind fails.
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

            if host_only == "localhost" || host_only == "127.0.0.1" || host_only == "[::1]" {
                let mut pac_script = String::from("function FindProxyForURL(url, host) {\n");

                let mut proxy_map: std::collections::HashMap<
                    String,
                    (Option<RegisteredProxy>, Option<RegisteredProxy>),
                > = std::collections::HashMap::new();

                // Scan proxies dir for JSON files
                if let Ok(entries) = std::fs::read_dir(&proxies_dir) {
                    for entry in entries.flatten() {
                        if let Some(ext) = entry.path().extension() {
                            if ext == "json" {
                                if let Ok(contents) = std::fs::read_to_string(entry.path()) {
                                    if let Ok(proxy_info) =
                                        serde_json::from_str::<RegisteredProxy>(&contents)
                                    {
                                        if proxy_info.proxy_ip.parse::<std::net::IpAddr>().is_err()
                                        {
                                            tracing::warn!(
                                                "Invalid IP address in proxy config: {}",
                                                proxy_info.proxy_ip
                                            );
                                            continue;
                                        }

                                        let tld = if proxy_info.tld.starts_with('.') {
                                            proxy_info.tld.clone()
                                        } else {
                                            format!(".{}", proxy_info.tld)
                                        };

                                        let is_atlas = entry
                                            .file_name()
                                            .to_string_lossy()
                                            .starts_with("atlas_");
                                        let entry = proxy_map.entry(tld).or_insert((None, None));

                                        if is_atlas {
                                            entry.1 = Some(proxy_info);
                                        } else {
                                            entry.0 = Some(proxy_info);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                for (tld, proxies) in proxy_map {
                    let mut proxy_string = String::new();

                    if let Some(native) = proxies.0 {
                        let ipv6 = if native.proxy_ip == "127.0.0.1" {
                            "[::1]"
                        } else {
                            &native.proxy_ip
                        };
                        proxy_string.push_str(&format!(
                            "PROXY {}:{}; PROXY {}:{}; ",
                            native.proxy_ip, native.proxy_port, ipv6, native.proxy_port
                        ));
                    }
                    if let Some(atlas) = proxies.1 {
                        let ipv6 = if atlas.proxy_ip == "127.0.0.1" {
                            "[::1]"
                        } else {
                            &atlas.proxy_ip
                        };
                        proxy_string.push_str(&format!(
                            "PROXY {}:{}; PROXY {}:{}; ",
                            atlas.proxy_ip, atlas.proxy_port, ipv6, atlas.proxy_port
                        ));
                    }
                    proxy_string.push_str("DIRECT");

                    pac_script.push_str(&format!(
                        "    if (shExpMatch(host, \"*{}\")) return \"{}\";\n",
                        tld, proxy_string
                    ));
                    pac_script.push_str(&format!(
                        "    if (shExpMatch(host, \"*{}.\")) return \"{}\";\n",
                        tld, proxy_string
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
        #[cfg(unix)]
        let mut sigterm =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).unwrap();

        #[cfg(unix)]
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = sigterm.recv() => {}
        }

        #[cfg(not(unix))]
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
        }
        info!("kinetic-pac shutting down, restoring OS proxy settings...");
        let _ = pac_manager.uninstall();
        std::process::exit(0);
    });

    axum::serve(listener, app).await?;
    Ok(())
}
