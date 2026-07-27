//! Linux-specific proxy configurators for KDE Plasma (`kwriteconfig5`) and GNOME (`gsettings`).

use super::super::*;
use std::process::Command;

/// Proxy configurator implementation for KDE/Plasma desktop environments using `kwriteconfig5`.
pub struct KdeConfigurator;

impl ProxyConfigurator for KdeConfigurator {
    fn install(&self, pac_url: &str) -> Result<(), PacError> {
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
            .map_err(|e| PacError::Command(format!("kwriteconfig5 failed: {}", e)))?;

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
            .map_err(|e| PacError::Command(format!("kwriteconfig5 failed: {}", e)))?;

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

    fn uninstall(&self) -> Result<(), PacError> {
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
            .map_err(|e| PacError::Command(format!("kwriteconfig5 uninstall failed: {}", e)))?;

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

    fn save_previous_state(&self) -> Result<SavedState, PacError> {
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
            macos_services: None,
        })
    }

    fn restore_state(&self, state: &SavedState) -> Result<(), PacError> {
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
                .map_err(|e| PacError::Command(format!("kwriteconfig5 restore failed: {}", e)))?;
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
                .map_err(|e| PacError::Command(format!("kwriteconfig5 restore failed: {}", e)))?;
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

/// Proxy configurator implementation for GNOME-based desktop environments using `gsettings`.
pub struct GnomeConfigurator;

impl ProxyConfigurator for GnomeConfigurator {
    fn install(&self, pac_url: &str) -> Result<(), PacError> {
        Command::new("gsettings")
            .args(["set", "org.gnome.system.proxy", "mode", "'auto'"])
            .status()
            .map_err(|e| PacError::Command(format!("gsettings failed: {}", e)))?;

        Command::new("gsettings")
            .args([
                "set",
                "org.gnome.system.proxy",
                "autoconfig-url",
                &format!("'{}'", pac_url),
            ])
            .status()
            .map_err(|e| PacError::Command(format!("gsettings failed: {}", e)))?;

        Ok(())
    }

    fn uninstall(&self) -> Result<(), PacError> {
        Command::new("gsettings")
            .args(["set", "org.gnome.system.proxy", "mode", "'none'"])
            .status()
            .map_err(|e| PacError::Command(format!("gsettings uninstall failed: {}", e)))?;

        Ok(())
    }

    fn save_previous_state(&self) -> Result<SavedState, PacError> {
        let proxy_type = Command::new("gsettings")
            .args(["get", "org.gnome.system.proxy", "mode"])
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

        let pac_url = Command::new("gsettings")
            .args(["get", "org.gnome.system.proxy", "autoconfig-url"])
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
            .filter(|s| !s.is_empty() && s != "''");

        Ok(SavedState {
            previous_pac_url: pac_url,
            proxy_type,
            macos_services: None,
        })
    }

    fn restore_state(&self, state: &SavedState) -> Result<(), PacError> {
        if let Some(ref proxy_type) = state.proxy_type {
            let _ = Command::new("gsettings")
                .args(["set", "org.gnome.system.proxy", "mode", proxy_type])
                .status();
        }
        if let Some(ref pac_url) = state.previous_pac_url {
            let _ = Command::new("gsettings")
                .args(["set", "org.gnome.system.proxy", "autoconfig-url", pac_url])
                .status();
        } else {
            let _ = Command::new("gsettings")
                .args(["set", "org.gnome.system.proxy", "autoconfig-url", "''"])
                .status();
        }
        Ok(())
    }
}

/// Detects the current Linux desktop environment via `XDG_CURRENT_DESKTOP`
/// and returns the appropriate proxy configurator implementation.
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
