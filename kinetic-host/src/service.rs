use anyhow::Result;
use service_manager::{
    ServiceInstallCtx, ServiceLabel, ServiceManager, ServiceStartCtx, ServiceStopCtx,
    ServiceUninstallCtx,
};
use std::env;

pub fn install_service() -> Result<()> {
    println!("Installing Kinetic Host service...");
    let label: ServiceLabel = "com.kinetic.host".parse()?;
    let manager = <dyn ServiceManager>::native()
        .map_err(|_| anyhow::anyhow!("Failed to detect native service manager"))?;
    let current_exe = env::current_exe()?;
    manager.install(ServiceInstallCtx {
        label: label.clone(),
        program: current_exe.clone(),
        args: vec!["start"
            .parse()
            .map_err(|_| anyhow::anyhow!("Failed to parse start"))?],
        contents: None,
        username: None,
        working_directory: None,
        environment: None,
        autostart: true,
        restart_policy: service_manager::RestartPolicy::default(),
    })?;

    println!("Service installed successfully. Run 'kinetic-host start-service' to begin.");
    Ok(())
}

pub fn uninstall_service() -> Result<()> {
    let label: ServiceLabel = "com.kinetic.host".parse()?;
    let manager = <dyn ServiceManager>::native()
        .map_err(|_| anyhow::anyhow!("Failed to detect native service manager"))?;
    manager.uninstall(ServiceUninstallCtx { label })?;
    println!("Service uninstalled.");
    Ok(())
}

pub fn start_background_service() -> Result<()> {
    let label: ServiceLabel = "com.kinetic.host".parse()?;
    let manager = <dyn ServiceManager>::native()
        .map_err(|_| anyhow::anyhow!("Failed to detect native service manager"))?;
    manager.start(ServiceStartCtx { label })?;
    println!("Service started.");
    Ok(())
}

pub fn stop_background_service() -> Result<()> {
    let label: ServiceLabel = "com.kinetic.host".parse()?;
    let manager = <dyn ServiceManager>::native()
        .map_err(|_| anyhow::anyhow!("Failed to detect native service manager"))?;
    manager.stop(ServiceStopCtx { label })?;
    println!("Service stopped.");
    Ok(())
}
