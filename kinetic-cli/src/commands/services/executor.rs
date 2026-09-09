//! System service lifecycle manager delegating execution to kinetic-daemon, kinetic-host, kinetic-node, and kinetic-dns.

use clap::Subcommand;

/// Lifecycle operations shared by all managed services.
#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum ServiceCommands {
    /// Install as a background system service (starts automatically on boot)
    Install,
    /// Uninstall the background service
    Uninstall,
    /// Start in the foreground (blocks the terminal)
    Run,
    /// Start as a background service (systemd / launchd)
    Start,
    /// Stop the background service
    Stop,
    /// Check the status of the background service
    Status,
    /// Tail the logs for the background service
    Logs,
    /// Check the static identity of the node (Host/Daemon only)
    Id,
    /// Configure the routing port (Host only)
    Port { port: Option<u16> },
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
                eprintln!(
                    "To view logs on macOS, check /tmp/{}.err or /tmp/{}.out (or appropriate log directory).",
                    binary, binary
                );
            } else {
                eprintln!("Logs are not supported on this OS.");
            }
            return Ok(());
        }
        _ => {}
    }

    // Map ServiceCommands → the argv the target binary understands.
    let (subcommand, extra_args) = match cmd {
        ServiceCommands::Install => ("install", vec![]),
        ServiceCommands::Uninstall => ("uninstall", vec![]),
        ServiceCommands::Run => ("run", vec![]),
        ServiceCommands::Start => ("start", vec![]),
        ServiceCommands::Stop => ("stop", vec![]),
        ServiceCommands::Id => ("id", vec![]),
        ServiceCommands::Port { port } => {
            if let Some(p) = port {
                ("port", vec![p.to_string()])
            } else {
                ("port", vec![])
            }
        }
        _ => unreachable!(),
    };

    // Verify the binary is on PATH before doing anything else.
    let binary_found = std::process::Command::new("which")
        .arg(binary)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    if !binary_found {
        let role_hint = if binary.ends_with("-daemon") {
            format!(
                "manage {} names and run the local P2P proxy",
                kinetic_core::constants::NSP_SUFFIX
            )
        } else if binary.ends_with("-host") {
            format!(
                "host a website or service reachable at a {} name (VPS / homelab)",
                kinetic_core::constants::NSP_SUFFIX
            )
        } else if binary.ends_with("-node") {
            format!(
                "run a full DHT node and contribute to the {} network",
                kinetic_core::constants::NSP
            )
        } else if binary.ends_with("-dns") {
            format!(
                "enable system-wide {} DNS resolution (e.g. for curl)",
                kinetic_core::constants::NSP_SUFFIX
            )
        } else if binary.ends_with("-pac") {
            format!(
                "manage system-wide automatic proxy configuration for {} names",
                kinetic_core::constants::NSP_SUFFIX
            )
        } else {
            "use this Kinetic component".to_string()
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
            .args(&extra_args)
            .status()
    } else {
        std::process::Command::new(binary)
            .arg(subcommand)
            .args(&extra_args)
            .status()
    };

    match status {
        Ok(s) if s.success() => Ok(()),
        Ok(s) => anyhow::bail!("'{}' exited with status: {}", binary, s),
        Err(e) => anyhow::bail!("Failed to run '{}': {}", binary, e),
    }
}
