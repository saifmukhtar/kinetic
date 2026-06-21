# install.ps1
# Kinetic Protocol Universal Installer for Windows

Write-Host "=== Kinetic Protocol Windows Installer ===" -ForegroundColor Cyan

# 1. Check for Administrator privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Please right-click PowerShell and select 'Run as Administrator' to install Kinetic."
    Exit
}

$InstallDir = "$env:ProgramFiles\Kinetic"
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir | Out-Null
}

# 2. Download Binaries
Write-Host "Downloading Kinetic Daemon..."
Invoke-WebRequest -Uri "https://github.com/saifmukhtar/kinetic/releases/latest/download/kinetic-daemon-windows.exe" -OutFile "$InstallDir\kinetic-daemon.exe"

Write-Host "Downloading Kinetic CLI..."
Invoke-WebRequest -Uri "https://github.com/saifmukhtar/kinetic/releases/latest/download/kinetic-cli-windows.exe" -OutFile "$InstallDir\kinetic-cli.exe"

# 3. Add to System PATH
$OldPath = [Environment]::GetEnvironmentVariable("Path", [EnvironmentVariableTarget]::Machine)
if ($OldPath -notmatch [regex]::Escape($InstallDir)) {
    Write-Host "Adding Kinetic to System PATH..."
    [Environment]::SetEnvironmentVariable("Path", "$OldPath;$InstallDir", [EnvironmentVariableTarget]::Machine)
}

# 4. Setup Windows Background Service
Write-Host "Configuring Windows Background Service..."
if (Get-Service -Name "KineticDaemon" -ErrorAction SilentlyContinue) {
    Stop-Service -Name "KineticDaemon" -Force
    # Native SC delete is most reliable
    & sc.exe delete KineticDaemon
    Start-Sleep -Seconds 2
}

New-Service -Name "KineticDaemon" -BinaryPathName "$InstallDir\kinetic-daemon.exe" -DisplayName "Kinetic Decentralized DNS Daemon" -StartupType Automatic -Description "Provides secure, decentralized resolution for .kin domains." | Out-Null
Start-Service -Name "KineticDaemon"

# 5. Configure OS DNS integration (Split-DNS via NRPT)
Write-Host "Configuring Windows NRPT Split-DNS natively..."
# Remove old rule if exists to prevent duplicates
Get-DnsClientNrptRule | Where-Object { $_.Namespace -eq '.kin' } | Remove-DnsClientNrptRule -Force -ErrorAction SilentlyContinue

# Add NRPT Rule for .kin routing specifically to localhost
Add-DnsClientNrptRule -Namespace ".kin" -NameServers "127.0.0.1"

Write-Host "=== Kinetic is successfully installed and running! ===" -ForegroundColor Green
Write-Host "Please restart your terminal window so you can start using 'kinetic-cli' commands!" -ForegroundColor Yellow
