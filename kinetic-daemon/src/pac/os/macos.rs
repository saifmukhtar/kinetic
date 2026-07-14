use super::super::*;
use std::process::Command;

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
