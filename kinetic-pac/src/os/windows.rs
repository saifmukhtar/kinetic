//! Windows-specific proxy configurator using PowerShell registry manipulation.

use super::super::*;
use std::process::Command;

/// Proxy configurator implementation for Windows using PowerShell registry modification.
#[cfg(target_os = "windows")]
pub struct WindowsConfigurator;

impl ProxyConfigurator for WindowsConfigurator {
    fn install(&self, pac_url: &str) -> Result<(), PacError> {
        // Set AutoConfigURL in the registry
        Command::new("powershell")
            .args([
                "-Command",
                &format!("Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' -Name AutoConfigURL -Value '{}'", pac_url),
            ])
            .status()
            .map_err(|e| PacError::Command(format!("powershell install failed: {}", e)))?;

        // Disable manual proxy if it was on (to ensure PAC is preferred)
        let _ = Command::new("powershell")
            .args([
                "-Command",
                "Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' -Name ProxyEnable -Value 0",
            ])
            .status();

        Ok(())
    }

    fn uninstall(&self) -> Result<(), PacError> {
        Command::new("powershell")
            .args([
                "-Command",
                "Remove-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' -Name AutoConfigURL -ErrorAction SilentlyContinue",
            ])
            .status()
            .map_err(|e| PacError::Command(format!("powershell uninstall failed: {}", e)))?;

        Ok(())
    }

    fn save_previous_state(&self) -> Result<SavedState, PacError> {
        let output = Command::new("powershell")
            .args([
                "-Command",
                "(Get-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings').AutoConfigURL",
            ])
            .output();

        let pac_url = match output {
            Ok(o) if o.status.success() => {
                let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
                if s.is_empty() {
                    None
                } else {
                    Some(s)
                }
            }
            _ => None,
        };

        Ok(SavedState {
            previous_pac_url: pac_url,
            proxy_type: None, // ProxyEnable isn't restored currently, but we could if needed
            macos_services: None,
        })
    }

    fn restore_state(&self, state: &SavedState) -> Result<(), PacError> {
        if let Some(ref pac_url) = state.previous_pac_url {
            let _ = Command::new("powershell")
                .args([
                    "-Command",
                    &format!("Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' -Name AutoConfigURL -Value '{}'", pac_url),
                ])
                .status();
        } else {
            let _ = self.uninstall();
        }
        Ok(())
    }
}
