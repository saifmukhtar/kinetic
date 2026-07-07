# install.ps1
# Kinetic Protocol Universal Installer for Windows

Write-Host "======================================================" -ForegroundColor Cyan
Write-Host "      Kinetic Protocol Universal Installer" -ForegroundColor Cyan
Write-Host "======================================================" -ForegroundColor Cyan
Write-Host ""

# 1. Check for Administrator privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Attempting to elevate privileges..." -ForegroundColor Yellow
    Start-Process powershell.exe -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    Exit
}

$InstallDir = "$env:ProgramFiles\Kinetic"

# 2. Check for existing installation
$ExistingBins = @()
$PossibleBins = @("kinetic-daemon", "kinetic-node", "kinetic-host", "kinetic-dns-server", "kinetic-cli", "kinetic-keygen")

if (Test-Path $InstallDir) {
    foreach ($bin in $PossibleBins) {
        if (Test-Path "$InstallDir\$bin.exe") {
            $ExistingBins += $bin
        }
    }
}

if ($ExistingBins.Count -gt 0) {
    Write-Host "Existing Kinetic installation detected: $($ExistingBins -join ', ')" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Please select an action:"
    Write-Host "1) Upgrade / Change Profile (removes old binaries and replaces them)"
    Write-Host "2) Full Cleanup (Nuke) (WARNING: removes everything INCLUDING your identity keys)"
    Write-Host "3) Exit"
    $UpgradeChoice = Read-Host "Selection [1-3]"

    if ($UpgradeChoice -eq "3") {
        Write-Host "Exiting."
        Exit
    } elseif ($UpgradeChoice -eq "2") {
        Write-Host ""
        Write-Host "!!! DANGER ZONE !!!" -ForegroundColor Red
        Write-Host "This will permanently delete your node identity, DNS keys, and all local storage." -ForegroundColor Red
        $ConfirmWipe = Read-Host "Type 'YES' to confirm full cleanup"
        if ($ConfirmWipe -ceq "YES") {
            Write-Host "Stopping and uninstalling services..."
            foreach ($bin in @("kinetic-daemon", "kinetic-node", "kinetic-host", "kinetic-dns-server")) {
                if (Test-Path "$InstallDir\$bin.exe") {
                    & "$InstallDir\$bin.exe" stop-service 2>$null
                    & "$InstallDir\$bin.exe" uninstall 2>$null
                }
            }
            Start-Sleep -Seconds 2
            Remove-Item -Path $InstallDir -Recurse -Force -ErrorAction SilentlyContinue

            # Clean OS-level DNS integration if exists
            Get-DnsClientNrptRule | Where-Object { $_.Namespace -eq '.kin' } | Remove-DnsClientNrptRule -Force -ErrorAction SilentlyContinue

            # Clean identity storage
            $ConfigDir = "$env:USERPROFILE\.config\kinetic"
            if (Test-Path $ConfigDir) {
                Remove-Item -Path $ConfigDir -Recurse -Force -ErrorAction SilentlyContinue
            }
            Write-Host "Full cleanup completed." -ForegroundColor Green
            Exit
        } else {
            Write-Host "Confirmation failed. Exiting."
            Exit
        }
    } elseif ($UpgradeChoice -eq "1") {
        Write-Host "Stopping services before upgrade..."
        foreach ($bin in @("kinetic-daemon", "kinetic-node", "kinetic-host", "kinetic-dns-server")) {
            if (Test-Path "$InstallDir\$bin.exe") {
                & "$InstallDir\$bin.exe" stop-service 2>$null
                & "$InstallDir\$bin.exe" uninstall 2>$null
            }
        }
        Start-Sleep -Seconds 2
        Remove-Item -Path "$InstallDir\*.exe" -Force -ErrorAction SilentlyContinue
    } else {
        Write-Host "Invalid choice. Exiting."
        Exit
    }
}

if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir | Out-Null
}

Write-Host "======================================================"
Write-Host "      Select Installation Profile"
Write-Host "======================================================"
Write-Host "1) Standard User  (Daemon + CLI)"
Write-Host "   -> For regular users wanting to resolve and register .kin domains safely."
Write-Host "2) Power User     (Daemon + CLI + DNS Server)"
Write-Host "   -> For advanced users wanting OS-level DNS integration (e.g., Pi-hole compatibility)."
Write-Host "3) Node Operator  (Node + CLI)"
Write-Host "   -> For infrastructure providers running P2P bootstrap nodes."
Write-Host "4) Host Operator  (Host + CLI)"
Write-Host "   -> For users hosting content or web services on a VPS."
Write-Host "5) Advanced       (Custom Selection)"
Write-Host "6) Exit"
Write-Host "======================================================"
$ProfileChoice = Read-Host "Profile Selection [1-6]"

$BinsToInstall = @("kinetic-cli")
$InstallDnsIntegration = $false

switch ($ProfileChoice) {
    "1" {
        $BinsToInstall += "kinetic-daemon"
    }
    "2" {
        $BinsToInstall += "kinetic-daemon", "kinetic-dns-server"
        $InstallDnsIntegration = $true
    }
    "3" {
        $BinsToInstall += "kinetic-node"
    }
    "4" {
        $BinsToInstall += "kinetic-host"
    }
    "5" {
        Write-Host ""
        Write-Host "Advanced Selection (CLI is always installed):"
        $AdvDaemon = Read-Host "Install Daemon? (y/N)"
        $AdvNode = Read-Host "Install Node? (y/N)"
        $AdvHost = Read-Host "Install Host? (y/N)"
        $AdvKeygen = Read-Host "Install Keygen? (y/N)"
        $AdvDns = Read-Host "Install DNS Server? (y/N)"

        if ($AdvDaemon -match "^[Yy]") { $BinsToInstall += "kinetic-daemon" }
        if ($AdvNode -match "^[Yy]") { $BinsToInstall += "kinetic-node" }
        if ($AdvHost -match "^[Yy]") { $BinsToInstall += "kinetic-host" }
        if ($AdvKeygen -match "^[Yy]") { $BinsToInstall += "kinetic-keygen" }
        if ($AdvDns -match "^[Yy]") { 
            $BinsToInstall += "kinetic-dns-server" 
            $AdvDnsInt = Read-Host "Enable OS-level DNS Integration? (y/N)"
            if ($AdvDnsInt -match "^[Yy]") { $InstallDnsIntegration = $true }
        }
    }
    "6" {
        Write-Host "Exiting."
        Exit
    }
    default {
        Write-Host "Invalid choice. Exiting."
        Exit
    }
}

Write-Host ""
Write-Host "The following binaries will be installed: $($BinsToInstall -join ', ')"
Write-Host "OS-level DNS integration enabled: $InstallDnsIntegration"
Write-Host ""

foreach ($bin in $BinsToInstall) {
    Write-Host "Downloading $bin..."
    Invoke-WebRequest -Uri "https://github.com/saifmukhtar/kinetic/releases/latest/download/$bin-windows.exe" -OutFile "$InstallDir\$bin.exe"
    
    # If it's a long running service, install and start it using the native command
    if ($bin -notin @("kinetic-cli", "kinetic-keygen")) {
        Write-Host "Installing system service for $bin..."
        & "$InstallDir\$bin.exe" install
        & "$InstallDir\$bin.exe" start-service
    }
}

# 3. Add to System PATH
$OldPath = [Environment]::GetEnvironmentVariable("Path", [EnvironmentVariableTarget]::Machine)
if ($OldPath -notmatch [regex]::Escape($InstallDir)) {
    Write-Host "Adding Kinetic to System PATH..."
    [Environment]::SetEnvironmentVariable("Path", "$OldPath;$InstallDir", [EnvironmentVariableTarget]::Machine)
}

# 4. OS-level DNS integration
if ($InstallDnsIntegration) {
    Write-Host "Configuring Windows NRPT Split-DNS natively..."
    Get-DnsClientNrptRule | Where-Object { $_.Namespace -eq '.kin' } | Remove-DnsClientNrptRule -Force -ErrorAction SilentlyContinue
    Add-DnsClientNrptRule -Namespace ".kin" -NameServers "127.0.0.1"
}

Write-Host ""
Write-Host "=== Kinetic is successfully installed and running! ===" -ForegroundColor Green
Write-Host "Please restart your terminal window so you can start using 'kinetic-cli' commands!" -ForegroundColor Yellow
Write-Host "Documentation & Guide: https://saifmukhtar.github.io/kinetic/" -ForegroundColor Cyan
