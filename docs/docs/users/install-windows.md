# Install on Windows

This guide covers installing Kinetic on Windows using the PowerShell installer.

::: tip Prefer a graphical interface?
Download the **Tauri desktop app** instead — it handles installation with a GUI and no PowerShell required. See the [welcome page](/users/) for the download link.
:::

## Prerequisites

- Windows 10 or later
- PowerShell 5.1 or later (pre-installed)
- Administrator account — the installer requests UAC elevation automatically

## Run the installer

Open **PowerShell** (no need to run as Administrator manually — the script self-elevates):

```powershell
irm https://kinetic.saifmukhtar.dev/install.ps1 | iex
```

If you get an execution policy error:

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
irm https://kinetic.saifmukhtar.dev/install.ps1 | iex
```

A UAC prompt will appear. Accept it — the installer needs admin to write to `Program Files` and register system services.

## Choose your profile

The installer presents an interactive menu. Use `↑` / `↓` to navigate, `Enter` to select:

| Profile | Installs | Best for |
|---|---|---|
| **Standard User** | Daemon + CLI | Registering names, resolving `.kin` |
| **Power User** | Daemon + CLI + DNS Server | OS-level `.kin` resolution in your browser |
| **Node Operator** | Node + CLI | Running a P2P infrastructure node |
| **Host Operator** | Host + CLI | Hosting content on a `.kin` address |
| **Custom** | You choose | Mixed setups |

## What the installer does

1. Downloads binaries from [GitHub Releases](https://github.com/saifmukhtar/kinetic/releases/latest) using `Invoke-WebRequest`
2. Verifies SHA256 checksums — aborts if they don't match
3. Copies binaries to `C:\Program Files\Kinetic\`
4. Adds `C:\Program Files\Kinetic\` to the system `PATH`
5. Runs `kinetic.exe setup` to generate your node identity (if none exists)
6. Installs and starts each service via Windows Service Manager

::: info Power User DNS on Windows
The Power User profile adds a **Name Resolution Policy Table (NRPT)** rule via `Add-DnsClientNrptRule` — this routes all `.kin` queries to `127.0.0.1` system-wide, giving every browser and application native `.kin` resolution.
:::

## Verify the installation

Open a **new** PowerShell window (to pick up the updated PATH), then:

```powershell
kinetic --version
kinetic-daemon --version
```

Check the daemon service is running:

```powershell
Get-Service kinetic-daemon
```

Status should be `Running`.

## First-time setup

The installer runs `kinetic setup` automatically. To run it manually:

```powershell
kinetic setup
```

This generates your **24-word seed phrase**. Write it down immediately — it is shown once and never again.

::: danger Back up your seed phrase
Your 24-word seed is the only way to recover your identity and names. See [Seed Backup](/users/seed-backup).
:::

## Data directory

Your data is stored at:

```
%LOCALAPPDATA%\kinetic\
├── identity.key          # Private key — never share this
├── api.token             # Local API bearer token
└── zones\
    └── yourname.kin.json # DNS zone for each registered name
```

::: info %LOCALAPPDATA% path
`%LOCALAPPDATA%` is usually `C:\Users\YourName\AppData\Local`. You can type this path directly in File Explorer or `cd $env:LOCALAPPDATA\kinetic` in PowerShell.
:::

## Windows Firewall

On first run, Windows Firewall will ask if Kinetic can communicate on the network. Click **Allow Access** for both private and public networks if you're running a node.

## Common issues

### Execution policy error

```
File cannot be loaded because running scripts is disabled on this system.
```

Fix:

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

### Port 53 conflict — DNS Client service

The **Windows DNS Client** service uses port 53. The Power User profile handles this via NRPT rules, which don't require binding port 53 directly. If you're seeing port conflicts, ensure you selected Power User (not a manual setup).

### PATH not updated in current session

The installer updates the **system PATH**, but your current PowerShell session won't see it. Open a new window.

### Upgrading

Re-run the installer. It detects existing binaries in `C:\Program Files\Kinetic\` and offers an upgrade or cleanup menu.

### Full uninstall

Re-run the installer and select **Full Cleanup**. This removes all binaries, services, NRPT rules, and local data.

::: danger Full cleanup deletes your identity
Ensure your 24-word seed phrase is backed up before running a full cleanup.
:::
