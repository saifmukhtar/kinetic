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
        let mut macos_services = std::collections::HashMap::new();
        if let Ok(output) = Command::new("networksetup")
            .arg("-listallnetworkservices")
            .output()
        {
            if let Ok(services_str) = String::from_utf8(output.stdout) {
                for service in services_str.lines().skip(1) {
                    if !service.starts_with('*') && !service.is_empty() {
                        if let Ok(url_output) = Command::new("networksetup")
                            .args(["-getautoproxyurl", service])
                            .output()
                        {
                            if let Ok(url_str) = String::from_utf8(url_output.stdout) {
                                if url_str.contains("Enabled: Yes") {
                                    if let Some(url_line) =
                                        url_str.lines().find(|l| l.starts_with("URL: "))
                                    {
                                        let url =
                                            url_line.trim_start_matches("URL: ").trim().to_string();
                                        if url != "(null)" && !url.is_empty() {
                                            macos_services.insert(service.to_string(), url);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok(SavedState {
            previous_pac_url: None,
            proxy_type: None,
            macos_services: Some(macos_services),
        })
    }

    fn restore_state(&self, state: &SavedState) -> Result<(), ProxyConfigError> {
        self.uninstall()?;
        if let Some(services) = &state.macos_services {
            for (service, url) in services {
                let _ = Command::new("networksetup")
                    .args(["-setautoproxyurl", service, url])
                    .status();
                let _ = Command::new("networksetup")
                    .args(["-setautoproxystate", service, "on"])
                    .status();
            }
        }
        Ok(())
    }
}
