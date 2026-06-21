#!/bin/bash
set -e

echo "=== Kinetic Daemon Installer (macOS) ==="

# 1. Download the latest binary
echo "Downloading Kinetic Daemon..."
curl -L https://github.com/saifmukhtar/kinetic/releases/latest/download/kinetic-daemon-macos -o /tmp/kinetic-daemon
sudo mv /tmp/kinetic-daemon /usr/local/bin/kinetic-daemon
sudo chmod +x /usr/local/bin/kinetic-daemon

# 2. Setup launchd background service
echo "Configuring background launchd service..."
cat << EOF > ~/Library/LaunchAgents/com.kinetic.daemon.plist
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.kinetic.daemon</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/kinetic-daemon</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
EOF

launchctl load ~/Library/LaunchAgents/com.kinetic.daemon.plist

# 3. Setup /etc/resolver for .kin domains exclusively
echo "Configuring OS DNS integration..."
sudo mkdir -p /etc/resolver
cat << EOF | sudo tee /etc/resolver/kin > /dev/null
nameserver 127.0.0.1
port 53
EOF

echo "=== Kinetic is installed and running! ==="
echo "Try visiting http://anyname.kin in your browser."
