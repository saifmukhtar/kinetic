use axum::{routing::get, Router};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Command;
use tracing::{error, info, warn};

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

pub struct KdeConfigurator;

impl ProxyConfigurator for KdeConfigurator {
    fn install(&self, pac_url: &str) -> Result<(), ProxyConfigError> {
        Command::new("kwriteconfig5")
            .args([
                "--file",
                "kioslaverc",
                "--group",
                "Proxy Settings",
                "--key",
                "ProxyType",
                "2",
            ])
            .status()
            .map_err(|e| ProxyConfigError::Command(format!("kwriteconfig5 failed: {}", e)))?;

        Command::new("kwriteconfig5")
            .args([
                "--file",
                "kioslaverc",
                "--group",
                "Proxy Settings",
                "--key",
                "Proxy Config Script",
                pac_url,
            ])
            .status()
            .map_err(|e| ProxyConfigError::Command(format!("kwriteconfig5 failed: {}", e)))?;

        let _ = Command::new("dbus-send")
            .args([
                "--type=signal",
                "/KIO/Scheduler",
                "org.kde.KIO.Scheduler.reparseSlaveConfiguration",
                "string:''",
            ])
            .status();

        Ok(())
    }

    fn uninstall(&self) -> Result<(), ProxyConfigError> {
        // Fallback to "No proxy" (type 0)
        Command::new("kwriteconfig5")
            .args([
                "--file",
                "kioslaverc",
                "--group",
                "Proxy Settings",
                "--key",
                "ProxyType",
                "0",
            ])
            .status()
            .map_err(|e| {
                ProxyConfigError::Command(format!("kwriteconfig5 uninstall failed: {}", e))
            })?;

        let _ = Command::new("dbus-send")
            .args([
                "--type=signal",
                "/KIO/Scheduler",
                "org.kde.KIO.Scheduler.reparseSlaveConfiguration",
                "string:''",
            ])
            .status();

        Ok(())
    }

    fn save_previous_state(&self) -> Result<SavedState, ProxyConfigError> {
        let proxy_type = Command::new("kreadconfig5")
            .args([
                "--file",
                "kioslaverc",
                "--group",
                "Proxy Settings",
                "--key",
                "ProxyType",
            ])
            .output()
            .ok()
            .and_then(|o| {
                if o.status.success() {
                    String::from_utf8(o.stdout).ok()
                } else {
                    None
                }
            })
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        let pac_url = Command::new("kreadconfig5")
            .args([
                "--file",
                "kioslaverc",
                "--group",
                "Proxy Settings",
                "--key",
                "Proxy Config Script",
            ])
            .output()
            .ok()
            .and_then(|o| {
                if o.status.success() {
                    String::from_utf8(o.stdout).ok()
                } else {
                    None
                }
            })
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        Ok(SavedState {
            previous_pac_url: pac_url,
            proxy_type: proxy_type.or(Some("0".to_string())),
        })
    }

    fn restore_state(&self, state: &SavedState) -> Result<(), ProxyConfigError> {
        if let Some(ref proxy_type) = state.proxy_type {
            Command::new("kwriteconfig5")
                .args([
                    "--file",
                    "kioslaverc",
                    "--group",
                    "Proxy Settings",
                    "--key",
                    "ProxyType",
                    proxy_type,
                ])
                .status()
                .map_err(|e| {
                    ProxyConfigError::Command(format!("kwriteconfig5 restore failed: {}", e))
                })?;
        }

        if let Some(ref pac_url) = state.previous_pac_url {
            Command::new("kwriteconfig5")
                .args([
                    "--file",
                    "kioslaverc",
                    "--group",
                    "Proxy Settings",
                    "--key",
                    "Proxy Config Script",
                    pac_url,
                ])
                .status()
                .map_err(|e| {
                    ProxyConfigError::Command(format!("kwriteconfig5 restore failed: {}", e))
                })?;
        }

        let _ = Command::new("dbus-send")
            .args([
                "--type=signal",
                "/KIO/Scheduler",
                "org.kde.KIO.Scheduler.reparseSlaveConfiguration",
                "string:''",
            ])
            .status();

        Ok(())
    }
}

pub struct GnomeConfigurator;

impl ProxyConfigurator for GnomeConfigurator {
    fn install(&self, pac_url: &str) -> Result<(), ProxyConfigError> {
        Command::new("gsettings")
            .args(["set", "org.gnome.system.proxy", "mode", "'auto'"])
            .status()
            .map_err(|e| ProxyConfigError::Command(format!("gsettings failed: {}", e)))?;

        Command::new("gsettings")
            .args([
                "set",
                "org.gnome.system.proxy",
                "autoconfig-url",
                &format!("'{}'", pac_url),
            ])
            .status()
            .map_err(|e| ProxyConfigError::Command(format!("gsettings failed: {}", e)))?;

        Ok(())
    }

    fn uninstall(&self) -> Result<(), ProxyConfigError> {
        Command::new("gsettings")
            .args(["set", "org.gnome.system.proxy", "mode", "'none'"])
            .status()
            .map_err(|e| ProxyConfigError::Command(format!("gsettings uninstall failed: {}", e)))?;

        Ok(())
    }

    fn save_previous_state(&self) -> Result<SavedState, ProxyConfigError> {
        Ok(SavedState {
            previous_pac_url: None,
            proxy_type: Some("'none'".to_string()),
        })
    }

    fn restore_state(&self, state: &SavedState) -> Result<(), ProxyConfigError> {
        if let Some(ref proxy_type) = state.proxy_type {
            let _ = Command::new("gsettings")
                .args(["set", "org.gnome.system.proxy", "mode", proxy_type])
                .status();
        }
        if let Some(ref pac_url) = state.previous_pac_url {
            let _ = Command::new("gsettings")
                .args([
                    "set",
                    "org.gnome.system.proxy",
                    "autoconfig-url",
                    &format!("'{}'", pac_url),
                ])
                .status();
        }
        Ok(())
    }
}

pub fn detect_linux_configurator() -> Box<dyn ProxyConfigurator> {
    let desktop = std::env::var("XDG_CURRENT_DESKTOP")
        .unwrap_or_default()
        .to_lowercase();

    match desktop.as_str() {
        s if s.contains("kde") || s.contains("plasma") => {
            info!("Detected KDE/Plasma environment for proxy configuration.");
            Box::new(KdeConfigurator)
        }
        s if s.contains("gnome") || s.contains("unity") || s.contains("budgie") => {
            info!("Detected GNOME/Unity environment for proxy configuration.");
            Box::new(GnomeConfigurator)
        }
        _ => {
            info!("Unknown or unsupported Linux desktop environment ({}). Using fallback proxy configurator.", desktop);
            Box::new(FallbackConfigurator)
        }
    }
}

#[cfg(target_os = "macos")]
pub struct MacosConfigurator;

#[cfg(target_os = "macos")]
impl ProxyConfigurator for MacosConfigurator {
    fn install(&self, pac_url: &str) -> Result<(), ProxyConfigError> {
        if let Ok(output) = Command::new("networksetup")
            .arg("-listallnetworkservices")
            .output()
        {
            if let Ok(services_str) = String::from_utf8(output.stdout) {
                for service in services_str.lines().skip(1) {
                    if !service.starts_with('*') && !service.is_empty() {
                        let _ = Command::new("networksetup")
                            .args(["-setautoproxyurl", service, pac_url])
                            .status();
                    }
                }
            }
        }
        Ok(())
    }

    fn uninstall(&self) -> Result<(), ProxyConfigError> {
        if let Ok(output) = Command::new("networksetup")
            .arg("-listallnetworkservices")
            .output()
        {
            if let Ok(services_str) = String::from_utf8(output.stdout) {
                for service in services_str.lines().skip(1) {
                    if !service.starts_with('*') && !service.is_empty() {
                        let _ = Command::new("networksetup")
                            .args(["-setautoproxystate", service, "off"])
                            .status();
                    }
                }
            }
        }
        Ok(())
    }

    fn save_previous_state(&self) -> Result<SavedState, ProxyConfigError> {
        Ok(SavedState {
            previous_pac_url: None,
            proxy_type: None,
        })
    }

    fn restore_state(&self, _state: &SavedState) -> Result<(), ProxyConfigError> {
        let _ = self.uninstall();
        Ok(())
    }
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
        _ => {
            warn!("Unsupported OS for automatic proxy configuration. Using fallback.");
            Box::new(FallbackConfigurator)
        }
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
        // Handle unclean shutdown recovery
        if self.lock_path.exists() {
            match File::open(&self.lock_path)
                .map(serde_json::from_reader::<_, SavedState>)
            {
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

    pub fn uninstall(&self) -> Result<(), ProxyConfigError> {
        if self.lock_path.exists() {
            match File::open(&self.lock_path)
                .map(serde_json::from_reader::<_, SavedState>)
            {
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

pub async fn start_pac_server(port: u16) -> anyhow::Result<()> {
    let pac_script = r#"
function FindProxyForURL(url, host) {
    if (shExpMatch(host, "*.kin")) return "PROXY 127.0.0.1:5463";
    if (shExpMatch(host, "*.kin.")) return "PROXY 127.0.0.1:5463";
    return "DIRECT";
}
"#
    .trim()
    .to_string();

    let app = Router::new().route(
        "/proxy.pac",
        get(move || async move {
            axum::response::Response::builder()
                .header("Content-Type", "application/x-ns-proxy-autoconfig")
                .body(pac_script.clone())
                .unwrap()
        }),
    );

    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!("Serving proxy.pac on http://{}/proxy.pac", addr);

    tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            error!("PAC server error: {}", e);
        }
    });

    Ok(())
}
