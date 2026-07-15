use clap::Subcommand;

/// Lifecycle operations shared by all managed services.
#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum ServiceCommands {
    /// Install as a background system service (starts automatically on boot)
    Install,
    /// Uninstall the background service
    Uninstall,
    /// Start in the foreground (blocks the terminal)
    Start,
    /// Start as a background service (systemd / launchd)
    Run,
    /// Stop the background service
    Stop,
    /// Check the status of the background service
    Status,
    /// Tail the logs for the background service
    Logs,
}

/// Handles service lifecycle commands for external Kinetic binaries.
///
/// Dispatches the user's requested command (e.g., `Install`, `Start`, `Stop`) to the
/// specified external binary. Supports privilege escalation if `needs_sudo` is true.
///
/// # Errors
/// Returns an `anyhow::Error` if the binary is not found on the `PATH`, or if the
/// external process fails to execute or exits with an error status.
pub async fn handle_service_command(
    binary: &str,
    cmd: ServiceCommands,
    needs_sudo: bool,
) -> anyhow::Result<()> {
    delegate_service(binary, &cmd, needs_sudo)
}

/// Delegate a lifecycle subcommand to an external Kinetic binary.
///
/// * `binary`    — name of the binary (e.g. `"kinetic-daemon"`), searched on `$PATH`
/// * `cmd`       — which lifecycle operation was requested
/// * `needs_sudo` — when `true` (DNS), prepend `sudo` on Unix and print a notice
fn delegate_service(binary: &str, cmd: &ServiceCommands, needs_sudo: bool) -> anyhow::Result<()> {
    match cmd {
        ServiceCommands::Status => {
            if cfg!(target_os = "linux") {
                let status = std::process::Command::new("systemctl")
                    .arg("is-active")
                    .arg(binary)
                    .status();
                if let Ok(s) = status {
                    if s.success() {
                        eprintln!("{} is running.", binary);
                    } else {
                        eprintln!("{} is NOT running.", binary);
                    }
                } else {
                    anyhow::bail!("Failed to check status with systemctl.");
                }
            } else if cfg!(target_os = "macos") {
                let status = std::process::Command::new("launchctl")
                    .arg("list")
                    .arg(binary)
                    .status();
                if let Ok(s) = status {
                    if s.success() {
                        eprintln!("{} is running.", binary);
                    } else {
                        eprintln!("{} is NOT running.", binary);
                    }
                } else {
                    anyhow::bail!("Failed to check status with launchctl.");
                }
            } else {
                eprintln!("Status check is not supported on this OS.");
            }
            return Ok(());
        }
        ServiceCommands::Logs => {
            if cfg!(target_os = "linux") {
                let status = std::process::Command::new("journalctl")
                    .arg("-u")
                    .arg(binary)
                    .arg("-f")
                    .status();
                if status.is_err() {
                    anyhow::bail!("Failed to tail logs with journalctl.");
                }
            } else if cfg!(target_os = "macos") {
                eprintln!("To view logs on macOS, check /tmp/{}.err or /tmp/{}.out (or appropriate log directory).", binary, binary);
            } else {
                eprintln!("Logs are not supported on this OS.");
            }
            return Ok(());
        }
        _ => {}
    }

    // Map ServiceCommands → the argv the target binary understands.
    let subcommand = match cmd {
        ServiceCommands::Install => "install",
        ServiceCommands::Uninstall => "uninstall",
        ServiceCommands::Start => "start",
        ServiceCommands::Run => "start-service",
        ServiceCommands::Stop => "stop-service",
        _ => unreachable!(),
    };

    // Verify the binary is on PATH before doing anything else.
    let binary_found = std::process::Command::new("which")
        .arg(binary)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    if !binary_found {
        let role_hint = match binary {
            "kinetic-daemon" => "manage .kin domain names and run the local P2P proxy",
            "kinetic-host" => "host a website or service reachable at a .kin name (VPS / homelab)",
            "kinetic-node" => "run a full DHT node and contribute to the Kinetic network",
            "kinetic-dns" => "enable system-wide .kin DNS resolution (e.g. for curl)",
            _ => "use this Kinetic component",
        };

        eprintln!();
        eprintln!("  Error: '{}' is not installed on this system.", binary);
        eprintln!();
        eprintln!("  '{}' is needed to {}.", binary, role_hint);
        eprintln!("  Install it and make sure it is available on your PATH,");
        eprintln!("  then re-run this command.");
        eprintln!();
        anyhow::bail!("{} not found on PATH.", binary);
    }

    // DNS requires root — warn the user before asking for their password.
    if needs_sudo {
        eprintln!();
        eprintln!("  Note: The Kinetic DNS server binds to port 53, which requires");
        eprintln!("        administrator / root access. You may be prompted for your password.");
        eprintln!();
    }

    // Build and exec the final command.
    let status = if needs_sudo && cfg!(unix) {
        std::process::Command::new("sudo")
            .arg(binary)
            .arg(subcommand)
            .status()
    } else {
        std::process::Command::new(binary).arg(subcommand).status()
    };

    match status {
        Ok(s) if s.success() => Ok(()),
        Ok(s) => anyhow::bail!("'{}' exited with status: {}", binary, s),
        Err(e) => anyhow::bail!("Failed to run '{}': {}", binary, e),
    }
}
