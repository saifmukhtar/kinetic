# Install Kinetic on Windows

This guide will walk you through installing the Kinetic daemon on Windows.

## Installation Steps

1. Open **PowerShell** as an Administrator. (Right-click the Start button, select "Windows PowerShell (Admin)" or "Terminal (Admin)").
2. Run the following command to download and execute the installer:

```powershell
Invoke-WebRequest -Uri "https://kinetic.saifmukhtar.dev/install.ps1" -OutFile "install.ps1"; .\install.ps1
```

**What this does:**
1. Installs the Kinetic binaries to `C:\Program Files\Kinetic\`.
2. Adds the folder to your system `PATH` so you can run `kinetic` from anywhere.
3. Creates the Kinetic data directory at `%APPDATA%\kinetic\`.

### 1. Verify the Installation

Restart your PowerShell window (still as Administrator) so the new `PATH` takes effect, then run:

```powershell
kinetic --version
kinetic daemon --help
```

### 2. Start the Daemon

The Kinetic daemon must be run in an Administrator PowerShell window.

```powershell
kinetic daemon
```

Look for the message `"Connected to DHT"` in the output logs.

::: tip
Windows Firewall may show a prompt asking if you want to allow `kinetic-daemon.exe` to communicate on the network. Make sure both Private and Public networks are checked and click **Allow access**.
:::

### 3. Initialize Your Identity

If this is your first time using Kinetic, generate your identity. Open a **new PowerShell window** (leave the daemon running) and run:

```powershell
kinetic seed init
```

::: danger
This command generates your master seed phrase. Follow the instructions on screen to back it up immediately! See the [Seed Backup Guide](/users/seed-backup) for more details.
:::

## Running Automatically

To start the Kinetic daemon automatically when you log in, you can use the Windows Task Scheduler.
Create a Basic Task that triggers "When I log on", set the action to "Start a program", and point it to `C:\Program Files\Kinetic\kinetic-daemon.exe`. Make sure to check "Run with highest privileges" in the task properties.

## Common Issues

### Execution Policy Error
If you receive an error about running scripts being disabled when trying to run `install.ps1`, change your execution policy temporarily:
```powershell
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
```
Then run the installation command again.

### Port 53 Conflicts
If the daemon fails to start because port 53 is in use, it is likely the Windows "DNS Client" service or Internet Connection Sharing (ICS). You may need to stop the conflicting service using the `services.msc` panel.
