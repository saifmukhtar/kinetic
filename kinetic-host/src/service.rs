//! Native OS service management (systemd, launchd, Windows Services) for Kinetic Host.

use anyhow::Result;
use service_manager::{
    ServiceInstallCtx, ServiceLabel, ServiceManager, ServiceStartCtx, ServiceStopCtx,
    ServiceUninstallCtx,
};
use std::env;

/// Installs the Kinetic Host as a native system service.
///
/// Configures the service to autostart on boot using the system's native
/// service manager (e.g., systemd, launchd).
///
/// # Errors
/// Returns an error if the native service manager cannot be detected, the
/// executable path cannot be resolved, or the service installation fails.
pub fn install_service() -> Result<()> {
    println!("Installing Kinetic Host service...");
    let label: ServiceLabel = format!("{}-host", kinetic_core::constants::NETWORK_ID).parse()?;
    let manager = <dyn ServiceManager>::native()
        .map_err(|_| anyhow::anyhow!("KIN-SYS-007: Failed to detect native OS service manager"))?;
    let current_exe = env::current_exe()
        .map_err(|e| anyhow::anyhow!("KIN-SYS-008: Failed to resolve current executable path: {}", e))?;
        
    manager.install(ServiceInstallCtx {
        label: label.clone(),
        program: current_exe.clone(),
        args: vec![
            "run"
                .parse()
                .map_err(|_| anyhow::anyhow!("KIN-SYS-009: Failed to parse arguments"))?,
        ],
        contents: None,
        username: std::env::var("SUDO_USER")
            .ok()
            .or_else(|| Some("nobody".to_string())),
        working_directory: None,
        environment: None,
        autostart: true,
        restart_policy: service_manager::RestartPolicy::default(),
    }).map_err(|e| anyhow::anyhow!("KIN-SYS-007: Failed to install background service: {}", e))?;

    println!("Service installed successfully. Run 'kinetic-host start' to begin.");
    Ok(())
}

/// Uninstalls the Kinetic Host system service.
///
/// Removes the service configuration from the system's native service manager.
///
/// # Errors
/// Returns an error if the native service manager cannot be detected or if
/// the uninstallation fails.
pub fn uninstall_service() -> Result<()> {
    let label: ServiceLabel = format!("{}-host", kinetic_core::constants::NETWORK_ID).parse()?;
    let manager = <dyn ServiceManager>::native()
        .map_err(|_| anyhow::anyhow!("KIN-SYS-007: Failed to detect native OS service manager"))?;
    manager.uninstall(ServiceUninstallCtx { label })
        .map_err(|e| anyhow::anyhow!("KIN-SYS-007: Failed to uninstall background service: {}", e))?;
    println!("Service uninstalled.");
    Ok(())
}

/// Starts the installed Kinetic Host system service.
///
/// Instructs the native service manager to start the background process.
///
/// # Errors
/// Returns an error if the native service manager cannot be detected or if
/// the service fails to start.
pub fn start_background_service() -> Result<()> {
    let label: ServiceLabel = format!("{}-host", kinetic_core::constants::NETWORK_ID).parse()?;
    let manager = <dyn ServiceManager>::native()
        .map_err(|_| anyhow::anyhow!("KIN-SYS-007: Failed to detect native OS service manager"))?;
    manager.start(ServiceStartCtx { label })
        .map_err(|e| anyhow::anyhow!("KIN-SYS-007: Failed to start background service: {}", e))?;
    println!("Service started.");
    Ok(())
}

/// Stops the currently running Kinetic Host system service.
///
/// Instructs the native service manager to stop the background process.
///
/// # Errors
/// Returns an error if the native service manager cannot be detected or if
/// the service fails to stop.
pub fn stop_background_service() -> Result<()> {
    let label: ServiceLabel = format!("{}-host", kinetic_core::constants::NETWORK_ID).parse()?;
    let manager = <dyn ServiceManager>::native()
        .map_err(|_| anyhow::anyhow!("KIN-SYS-007: Failed to detect native OS service manager"))?;
    manager.stop(ServiceStopCtx { label })
        .map_err(|e| anyhow::anyhow!("KIN-SYS-007: Failed to stop background service: {}", e))?;
    println!("Service stopped.");
    Ok(())
}
