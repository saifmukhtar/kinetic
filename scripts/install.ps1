# install.ps1
# Kinetic Protocol Universal Installer for Windows

$Host.UI.RawUI.CursorSize = 0
[Console]::CursorVisible = $false

# Print branding banner
function Print-Banner {
    Write-Host "   _  _____ _   _ _____ _____ ___ ____ " -ForegroundColor Cyan
    Write-Host "  | |/ /_ _| \ | | ____|_   _|_ _/ ___|" -ForegroundColor Cyan
    Write-Host "  | ' / | ||  \| |  _|   | |  | | |    " -ForegroundColor Cyan
    Write-Host "  | . \ | || |\  | |___  | |  | | |___ " -ForegroundColor Cyan
    Write-Host "  |_|\_\___|_| \_|_____| |_| |___\____|" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Welcome to the Kinetic Protocol Installer!" -ForegroundColor Green
    Write-Host "  Setup your node, daemon, and DNS natively." -ForegroundColor Yellow
    Write-Host ""
}

function Show-Menu {
    param (
        [string]$Prompt,
        [string[]]$Options,
        [string[]]$Descriptions = @()
    )
    $cur = 0
    $count = $Options.Count

    Clear-Host
    Print-Banner
    Write-Host $Prompt

    $Top = [Console]::CursorTop
    while ($true) {
        [Console]::SetCursorPosition(0, $Top)
        for ($i = 0; $i -lt $count; $i++) {
            if ($i -eq $cur) {
                Write-Host "  > $($Options[$i])".PadRight(80) -ForegroundColor Green
            } else {
                Write-Host "    $($Options[$i])".PadRight(80)
            }
        }
        
        Write-Host ""
        if ($Descriptions.Count -gt 0) {
            Write-Host "  i $($Descriptions[$cur])".PadRight(100) -ForegroundColor Yellow
        } else {
            Write-Host "".PadRight(100)
        }

        $Key = [Console]::ReadKey($true).Key
        if ($Key -eq 'UpArrow') {
            $cur--
            if ($cur -lt 0) { $cur = $count - 1 }
        } elseif ($Key -eq 'DownArrow') {
            $cur++
            if ($cur -ge $count) { $cur = 0 }
        } elseif ($Key -eq 'Enter') {
            break
        }
    }
    
    [Console]::SetCursorPosition(0, $Top + $count + 2)
    [Console]::CursorVisible = $true
    return $cur
}

function Show-MultiMenu {
    param (
        [string]$Prompt,
        [string[]]$Options,
        [string[]]$Descriptions = @()
    )
    $cur = 0
    $count = $Options.Count
    $selected = @(0) * $count

    Clear-Host
    Print-Banner
    Write-Host $Prompt

    $Top = [Console]::CursorTop
    while ($true) {
        [Console]::SetCursorPosition(0, $Top)
        for ($i = 0; $i -lt $count; $i++) {
            $checkbox = if ($selected[$i] -eq 1) { "[x]" } else { "[ ]" }
            if ($i -eq $cur) {
                Write-Host "  > $checkbox $($Options[$i])".PadRight(80) -ForegroundColor Green
            } else {
                Write-Host "    $checkbox $($Options[$i])".PadRight(80)
            }
        }
        
        Write-Host ""
        if ($Descriptions.Count -gt 0) {
            Write-Host "  i $($Descriptions[$cur])".PadRight(100) -ForegroundColor Yellow
        } else {
            Write-Host "".PadRight(100)
        }

        $KeyInfo = [Console]::ReadKey($true)
        $Key = $KeyInfo.Key
        $Char = $KeyInfo.KeyChar
        
        if ($Key -eq 'UpArrow') {
            $cur--
            if ($cur -lt 0) { $cur = $count - 1 }
        } elseif ($Key -eq 'DownArrow') {
            $cur++
            if ($cur -ge $count) { $cur = 0 }
        } elseif ($Char -eq ' ') {
            if ($selected[$cur] -eq 1) { $selected[$cur] = 0 } else { $selected[$cur] = 1 }
        } elseif ($Key -eq 'Enter') {
            break
        }
    }
    
    [Console]::SetCursorPosition(0, $Top + $count + 2)
    [Console]::CursorVisible = $true
    
    $result = @()
    for ($i = 0; $i -lt $count; $i++) {
        if ($selected[$i] -eq 1) { $result += $i }
    }
    return $result
}

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
    $Opts = @("Upgrade / Change Profile", "Full Cleanup (Nuke)", "Exit")
    $Choice = Show-Menu -Prompt "Existing installation detected. Action:" -Options $Opts

    if ($Choice -eq 2) {
        Exit
    } elseif ($Choice -eq 1) {
        Clear-Host
        Write-Host "!!! DANGER ZONE !!!" -ForegroundColor Red
        Write-Host "This will permanently delete your node identity, DNS keys, and all local storage." -ForegroundColor Red
        $ConfirmWipe = Read-Host "Type 'YES' to confirm full cleanup"
        if ($ConfirmWipe -ceq "YES") {
            foreach ($bin in $ExistingBins) {
                & "$InstallDir\$bin.exe" stop-service 2>$null
                & "$InstallDir\$bin.exe" uninstall 2>$null
            }
            Start-Sleep -Seconds 2
            Remove-Item -Path $InstallDir -Recurse -Force -ErrorAction SilentlyContinue
            Get-DnsClientNrptRule | Where-Object { $_.Namespace -eq '.kin' } | Remove-DnsClientNrptRule -Force -ErrorAction SilentlyContinue
            $ConfigDir = "$env:USERPROFILE\.config\kinetic"
            if (Test-Path $ConfigDir) { Remove-Item -Path $ConfigDir -Recurse -Force -ErrorAction SilentlyContinue }
            Write-Host "Full cleanup completed." -ForegroundColor Green
            Exit
        } else { Exit }
    } elseif ($Choice -eq 0) {
        foreach ($bin in $ExistingBins) {
            & "$InstallDir\$bin.exe" stop-service 2>$null
            & "$InstallDir\$bin.exe" uninstall 2>$null
        }
        Start-Sleep -Seconds 2
        Remove-Item -Path "$InstallDir\*.exe" -Force -ErrorAction SilentlyContinue
    }
    Clear-Host
}

if (-not (Test-Path $InstallDir)) { New-Item -ItemType Directory -Path $InstallDir | Out-Null }

$Opts = @(
    "Standard User   (Daemon + CLI)",
    "Power User      (Daemon + CLI + DNS Server)",
    "Node Operator   (Node + CLI)",
    "Host Operator   (Host + CLI)",
    "Custom / Adv.   (Choose components)",
    "Exit"
)
$Descs = @(
    "For regular users wanting to resolve and register .kin domains safely.",
    "For advanced users wanting OS-level DNS integration (e.g., Pi-hole compatibility).",
    "For infrastructure providers running P2P bootstrap nodes.",
    "For users hosting content or web services on a VPS.",
    "Manually select which Kinetic components you want to install.",
    "Exit the installer without making changes."
)
$Profile = Show-Menu -Prompt "Select Installation Profile:" -Options $Opts -Descriptions $Descs

$BinsToInstall = @("kinetic-cli")
$InstallDns = $false

switch ($Profile) {
    0 { $BinsToInstall += "kinetic-daemon" }
    1 { $BinsToInstall += "kinetic-daemon", "kinetic-dns-server"; $InstallDns = $true }
    2 { $BinsToInstall += "kinetic-node" }
    3 { $BinsToInstall += "kinetic-host" }
    4 { 
        Clear-Host
        $CustomOpts = @("kinetic-daemon", "kinetic-dns-server", "kinetic-node", "kinetic-host")
        $CustomDescs = @(
            "Runs the VDF and P2P client for .kin resolution.",
            "System-wide DNS server for local OS integration.",
            "P2P bootstrap node for infrastructure providers.",
            "Content hosting server for static files and web services."
        )
        $Selected = Show-MultiMenu -Prompt "Select components to install (Space to toggle, Enter to confirm):" -Options $CustomOpts -Descriptions $CustomDescs
        foreach ($opt in $Selected) {
            if ($opt -eq 0) { $BinsToInstall += "kinetic-daemon" }
            if ($opt -eq 1) { $BinsToInstall += "kinetic-dns-server"; $InstallDns = $true }
            if ($opt -eq 2) { $BinsToInstall += "kinetic-node" }
            if ($opt -eq 3) { $BinsToInstall += "kinetic-host" }
        }
    }
    5 { Exit }
}

Write-Host "`nInstalling: $($BinsToInstall -join ', ')" -ForegroundColor Yellow

foreach ($bin in $BinsToInstall) {
    Write-Host "Downloading $bin..."
    Invoke-WebRequest -Uri "https://github.com/saifmukhtar/kinetic/releases/latest/download/$bin-windows.exe" -OutFile "$InstallDir\$bin.exe"
    
    if ($bin -ne "kinetic-cli") {
        & "$InstallDir\$bin.exe" install
        & "$InstallDir\$bin.exe" start-service
    }
}

$OldPath = [Environment]::GetEnvironmentVariable("Path", [EnvironmentVariableTarget]::Machine)
if ($OldPath -notmatch [regex]::Escape($InstallDir)) {
    [Environment]::SetEnvironmentVariable("Path", "$OldPath;$InstallDir", [EnvironmentVariableTarget]::Machine)
}

if ($InstallDns) {
    Write-Host "Configuring Windows NRPT Split-DNS natively..."
    Get-DnsClientNrptRule | Where-Object { $_.Namespace -eq '.kin' } | Remove-DnsClientNrptRule -Force -ErrorAction SilentlyContinue
    Add-DnsClientNrptRule -Namespace ".kin" -NameServers "127.0.0.1"
}

Write-Host "`n=== Kinetic installed successfully! ===" -ForegroundColor Green
Write-Host "Documentation & Guide: " -ForegroundColor Cyan -NoNewline; Write-Host "https://kinetic.saifmukhtar.dev"
if ($BinsToInstall -contains "kinetic-daemon") {
    Write-Host "Local Dashboard:       " -ForegroundColor Cyan -NoNewline; Write-Host "http://localhost:16002`n"
} else {
    Write-Host ""
}
