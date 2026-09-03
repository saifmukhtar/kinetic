//! Local server and configurator for routing `.kin` domains using Proxy Auto-Configuration (PAC).
//!
//! This daemon provides an HTTP endpoint serving a dynamically updated `proxy.pac` script.
//! It seamlessly integrates with OS-level proxy settings on Windows, macOS, and Linux,
//! routing requests for `.kin` and other configured domains to the Kinetic HTTP proxy,
//! while allowing normal internet traffic to bypass the proxy.

use axum::{Router, routing::get};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use service_manager::{
    ServiceInstallCtx, ServiceLabel, ServiceManager, ServiceStartCtx, ServiceStopCtx,
    ServiceUninstallCtx,
};
use std::env;
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
    fn save_state(&self) -> Result<SavedState, PacError>;

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
    fn save_state(&self) -> Result<SavedState, PacError> {
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
            lock_path: config_dir.join("kinetic.kin"),
        }
    }

    #[cfg(test)]
    pub fn new_for_test(
        config_dir: &std::path::Path,
        configurator: Box<dyn ProxyConfigurator>,
    ) -> Self {
        Self {
            configurator,
            lock_path: config_dir.join("kinetic.kin"),
        }
    }

    /// Backs up current OS proxy settings, locks the state, and installs the new PAC URL.
    ///
    /// # Errors
    /// Returns a [`PacError`] if IO fails on the lockfile or the OS rejects the configuration.
    pub fn install(&self, pac_url: &str) -> Result<(), PacError> {
        if self.lock_path.exists()
            && let Ok(Ok(saved)) =
                File::open(&self.lock_path).map(serde_json::from_reader::<_, SavedState>)
            {
                let _ = self.configurator.restore_state(&saved);
            }
        let previous = self.configurator.save_state()?;
        let tmp_path = self.lock_path.with_extension("tmp");
        if let Ok(file) = File::create(&tmp_path) {
            let _ = serde_json::to_writer(file, &previous);
            let _ = std::fs::rename(&tmp_path, &self.lock_path);
        }

        if let Some(parent) = self.lock_path.parent() {
            let original_js = parent.join("original_pac.js");
            let _ = std::fs::remove_file(&original_js);

            if let Some(ref old_url) = previous.previous_pac_url {
                if old_url.starts_with("http") {
                    if let Ok(resp) = reqwest::blocking::get(old_url)
                        && let Ok(text) = resp.text() {
                            let _ = std::fs::write(&original_js, text);
                            tracing::info!(
                                "Successfully downloaded original PAC script for passthrough merging."
                            );
                        }
                } else if old_url.starts_with("file://")
                    && let Ok(text) = std::fs::read_to_string(old_url.trim_start_matches("file://"))
                    {
                        let _ = std::fs::write(&original_js, text);
                        tracing::info!(
                            "Successfully read local original PAC script for passthrough merging."
                        );
                    }
            }
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
            let mut os_was_tampered = false;

            // Drift Check: See if the OS proxy is still set to Kinetic.
            // If the user manually changed it while we were running, we must not overwrite their changes!
            if let Ok(current_state) = self.configurator.save_state() {
                if let Some(ref macos_services) = current_state.macos_services {
                    if macos_services.is_empty() {
                        os_was_tampered = true;
                    } else {
                        for url in macos_services.values() {
                            if !url.contains("16001") {
                                os_was_tampered = true;
                                break;
                            }
                        }
                    }
                } else if let Some(ref current_pac) = current_state.previous_pac_url {
                    if !current_pac.contains("16001") {
                        os_was_tampered = true;
                    }
                } else {
                    os_was_tampered = true;
                }
            }

            if os_was_tampered {
                tracing::info!(
                    "OS proxy settings were manually changed by the user. Leaving them intact and removing lockfile."
                );
            } else if let Ok(Ok(saved)) =
                File::open(&self.lock_path).map(serde_json::from_reader::<_, SavedState>)
            {
                let _ = self.configurator.restore_state(&saved);
                tracing::info!("Successfully restored original OS proxy settings");
            } else {
                let _ = self.configurator.uninstall();
            }

            if let Some(parent) = self.lock_path.parent() {
                let _ = std::fs::remove_file(parent.join("original_pac.js"));
            }
            let _ = std::fs::remove_file(&self.lock_path);
        } else {
            let _ = self.configurator.uninstall();
        }
        Ok(())
    }
}

/// Represents a serialized proxy backend registered by other Kinetic components.
#[derive(Deserialize, Serialize, Debug)]
struct RegisteredProxy {
    nsp: String,
    proxy_port: u16,
    #[serde(default = "default_ip")]
    proxy_ip: String,
}

/// Default proxy IP (localhost) if none is provided in the JSON registry.
fn default_ip() -> String {
    "127.0.0.1".to_string()
}

#[derive(Parser)]
#[command(
    name = "kinetic-pac-server",
    version = "0.1.0",
    author = "Kinetic Protocol"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Install the PAC server as a background service
    Install,
    /// Uninstall the PAC server background service
    Uninstall,
    /// Start the PAC server (foreground)
    Run,
    /// Start the PAC server service (background)
    Start,
    /// Stop the PAC server service (background)
    Stop,
}

fn install_service() -> anyhow::Result<()> {
    println!("Installing Kinetic PAC Server service...");
    let label: ServiceLabel = format!("{}-pac", kinetic_core::constants::NSP).parse()?;
    let manager = <dyn ServiceManager>::native()
        .map_err(|e| anyhow::anyhow!("Failed to detect native service manager: {}", e))?;
    let current_exe = env::current_exe()?;
    manager.install(ServiceInstallCtx {
        label: label.clone(),
        program: current_exe.clone(),
        args: vec!["run".into()],
        contents: None,
        username: None,
        working_directory: None,
        environment: None,
        autostart: true,
        restart_policy: service_manager::RestartPolicy::default(),
    })?;

    println!(
        "Service installed successfully. Run '{}-pac start' to begin.",
        kinetic_core::constants::NSP
    );
    Ok(())
}

fn uninstall_service() -> anyhow::Result<()> {
    let label: ServiceLabel = format!("{}-pac", kinetic_core::constants::NSP).parse()?;
    let manager = <dyn ServiceManager>::native()
        .map_err(|e| anyhow::anyhow!("Failed to detect native service manager: {}", e))?;
    manager.uninstall(ServiceUninstallCtx { label })?;

    // Also remove OS settings just in case it's currently installed
    let base_dir = dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("kinetic")
        .join("pac_router");
    let pac_manager = PacManager::new(&base_dir);
    let _ = pac_manager.uninstall();

    println!("Service uninstalled and OS settings restored.");
    Ok(())
}

fn start_background_service() -> anyhow::Result<()> {
    let label: ServiceLabel = format!("{}-pac", kinetic_core::constants::NSP).parse()?;
    let manager = <dyn ServiceManager>::native()
        .map_err(|e| anyhow::anyhow!("Failed to detect native service manager: {}", e))?;
    manager.start(ServiceStartCtx { label })?;
    println!("Service started.");
    Ok(())
}

fn stop_background_service() -> anyhow::Result<()> {
    let label: ServiceLabel = format!("{}-pac", kinetic_core::constants::NSP).parse()?;
    let manager = <dyn ServiceManager>::native()
        .map_err(|e| anyhow::anyhow!("Failed to detect native service manager: {}", e))?;
    manager.stop(ServiceStopCtx { label })?;
    println!("Service stopped.");
    Ok(())
}

pub fn build_pac_script(proxies_dir: &std::path::Path) -> String {
    let mut pac_script = String::from("function FindProxyForURL(url, host) {\n");

    let mut proxy_map: std::collections::HashMap<
        String,
        (Option<RegisteredProxy>, Option<RegisteredProxy>),
    > = std::collections::HashMap::new();

    // Scan proxies dir for JSON files
    if let Ok(entries) = std::fs::read_dir(proxies_dir) {
        for entry in entries.flatten() {
            if let Some(ext) = entry.path().extension()
                && ext == "json"
                    && let Ok(contents) = std::fs::read_to_string(entry.path())
                        && let Ok(proxy_info) = serde_json::from_str::<RegisteredProxy>(&contents) {
                            if proxy_info.proxy_ip.parse::<std::net::IpAddr>().is_err() {
                                tracing::warn!(
                                    "Invalid IP address in proxy config: {}",
                                    proxy_info.proxy_ip
                                );
                                continue;
                            }

                            let nsp = if proxy_info.nsp.starts_with('.') {
                                proxy_info.nsp.clone()
                            } else {
                                format!(".{}", proxy_info.nsp)
                            };

                            let is_atlas =
                                entry.file_name().to_string_lossy().starts_with("atlas_");
                            let entry = proxy_map.entry(nsp).or_insert((None, None));

                            if is_atlas {
                                entry.1 = Some(proxy_info);
                            } else {
                                entry.0 = Some(proxy_info);
                            }
                        }
        }
    }

    for (nsp, proxies) in proxy_map {
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
            nsp, proxy_string
        ));
        pac_script.push_str(&format!(
            "    if (shExpMatch(host, \"*{}.\")) return \"{}\";\n",
            nsp, proxy_string
        ));
    }

    let mut passthrough_injected = false;
    if let Some(parent) = proxies_dir.parent() {
        let original_js_path = parent.join("original_pac.js");
        if let Ok(mut original_script) = std::fs::read_to_string(&original_js_path) {
            original_script = original_script.replace("FindProxyForURL", "OriginalFindProxyForURL");
            pac_script.push_str("    return OriginalFindProxyForURL(url, host);\n}\n\n");
            pac_script.push_str("// --- USER'S ORIGINAL PAC SCRIPT BELOW ---\n");
            pac_script.push_str(&original_script);
            passthrough_injected = true;
        }
    }

    if !passthrough_injected {
        pac_script.push_str("    return \"DIRECT\";\n}\n");
    }

    pac_script
}

/// Runs the PAC HTTP Server and applies OS proxy rules
async fn run_server() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let base_dir = dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("kinetic")
        .join("pac_router");

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
                let pac_script = build_pac_script(&proxies_dir);

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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Some(Commands::Install) => {
            install_service()?;
        }
        Some(Commands::Uninstall) => {
            uninstall_service()?;
        }
        Some(Commands::Start) => {
            start_background_service()?;
        }
        Some(Commands::Stop) => {
            stop_background_service()?;
        }
        Some(Commands::Run) | None => {
            run_server().await?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    struct MockConfigurator;
    impl ProxyConfigurator for MockConfigurator {
        fn install(&self, _pac_url: &str) -> Result<(), PacError> {
            Ok(())
        }
        fn uninstall(&self) -> Result<(), PacError> {
            Ok(())
        }
        fn save_state(&self) -> Result<SavedState, PacError> {
            Ok(SavedState {
                previous_pac_url: Some("http://old.pac".to_string()),
                proxy_type: Some("1".to_string()),
                macos_services: None,
            })
        }
        fn restore_state(&self, _state: &SavedState) -> Result<(), PacError> {
            Ok(())
        }
    }

    #[test]
    fn test_pac_lock_file_persistence() {
        let dir = tempdir().unwrap();
        let manager = PacManager::new_for_test(dir.path(), Box::new(MockConfigurator));

        assert!(!manager.lock_path.exists());
        manager.install("http://127.0.0.1:16001/proxy.pac").unwrap();
        assert!(manager.lock_path.exists());

        let contents = fs::read_to_string(&manager.lock_path).unwrap();
        let saved: SavedState = serde_json::from_str(&contents).unwrap();
        assert_eq!(saved.previous_pac_url.unwrap(), "http://old.pac");
        assert_eq!(saved.proxy_type.unwrap(), "1");

        manager.uninstall().unwrap();
        assert!(!manager.lock_path.exists());
    }

    #[test]
    fn test_pac_script_multi_network() {
        let dir = tempdir().unwrap();

        let kin_proxy = RegisteredProxy {
            nsp: ".kin".to_string(),
            proxy_port: 16001,
            proxy_ip: "127.0.255.1".to_string(),
        };
        let uni_proxy = RegisteredProxy {
            nsp: ".uni".to_string(),
            proxy_port: 16002,
            proxy_ip: "127.0.255.2".to_string(),
        };

        fs::write(
            dir.path().join("kin.json"),
            serde_json::to_string(&kin_proxy).unwrap(),
        )
        .unwrap();
        fs::write(
            dir.path().join("uni.json"),
            serde_json::to_string(&uni_proxy).unwrap(),
        )
        .unwrap();

        let script = build_pac_script(dir.path());
        assert!(script.contains("function FindProxyForURL"));
        assert!(script.contains("if (shExpMatch(host, \"*.kin\"))"));
        assert!(script.contains("127.0.255.1:16001"));
        assert!(script.contains("if (shExpMatch(host, \"*.uni\"))"));
        assert!(script.contains("127.0.255.2:16002"));
        assert!(script.ends_with("    return \"DIRECT\";\n}\n"));
    }

    #[test]
    fn test_pac_script_passthrough_merge() {
        let dir = tempdir().unwrap();
        let original_pac = "function FindProxyForURL(url, host) { return \"PROXY 10.0.0.5:80\"; }";
        fs::write(dir.path().join("original_pac.js"), original_pac).unwrap();

        let proxies_dir = dir.path().join("proxies");
        fs::create_dir_all(&proxies_dir).unwrap();

        let script = build_pac_script(&proxies_dir);
        assert!(script.contains("function OriginalFindProxyForURL(url, host)"));
        assert!(script.contains("return OriginalFindProxyForURL(url, host);"));
        assert!(script.contains("return \"PROXY 10.0.0.5:80\";"));
    }
}
