@echo off
echo === Kinetic Daemon Installer (Windows) ===

:: Request administrator privileges to set DNS and Services
:: (Assuming this script is already run as Admin)

:: 1. Setup Windows Service (requires nssm or native sc)
echo Configuring background Windows Service...
mkdir "C:\Program Files\Kinetic" 2>nul
:: copy kinetic-daemon.exe "C:\Program Files\Kinetic\kinetic-daemon.exe"
sc create KineticDaemon binPath= "C:\Program Files\Kinetic\kinetic-daemon.exe" start= auto
sc start KineticDaemon

:: 2. Set OS DNS to localhost. 
:: Because Windows doesn't easily support domain-specific routing (like /etc/resolver),
:: we set the primary DNS to localhost so Kinetic can intercept .kin, and it will forward normal domains to Cloudflare.
echo Configuring OS DNS integration...
netsh interface ipv4 set dnsservers name="Wi-Fi" source=static address=127.0.0.1 register=primary validate=no
netsh interface ipv4 set dnsservers name="Ethernet" source=static address=127.0.0.1 register=primary validate=no

echo === Kinetic is installed and running! ===
echo Try visiting http://anyname.kin in your browser.
pause
