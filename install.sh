#!/bin/bash
set -e

echo "=== Kinetic Protocol Universal Installer ==="

# 1. Detect OS and Architecture
OS="$(uname -s)"
ARCH="$(uname -m)"

ASSET_SUFFIX=""
if [ "$OS" = "Linux" ]; then
    ASSET_SUFFIX="linux"
elif [ "$OS" = "Darwin" ]; then
    ASSET_SUFFIX="macos"
else
    echo "Unsupported OS: $OS"
    exit 1
fi

echo "Detected OS: $OS ($ARCH)"

# 2. Download Binaries
echo "Downloading Kinetic Daemon..."
curl -sL "https://github.com/saifmukhtar/kinetic/releases/latest/download/kinetic-daemon-$ASSET_SUFFIX" -o /tmp/kinetic-daemon
sudo cp /tmp/kinetic-daemon /usr/local/bin/kinetic-daemon
sudo chmod +x /usr/local/bin/kinetic-daemon

echo "Downloading Kinetic CLI..."
curl -sL "https://github.com/saifmukhtar/kinetic/releases/latest/download/kinetic-cli-$ASSET_SUFFIX" -o /tmp/kinetic-cli
sudo cp /tmp/kinetic-cli /usr/local/bin/kinetic-cli
sudo chmod +x /usr/local/bin/kinetic-cli

# 3. Setup Background Service & DNS integration based on OS
if [ "$OS" = "Linux" ]; then
    echo "Configuring background systemd service..."
    cat << EOF | sudo tee /etc/systemd/system/kinetic-daemon.service > /dev/null
[Unit]
Description=Kinetic Decentralized DNS Daemon
After=network.target

[Service]
ExecStart=/usr/local/bin/kinetic-daemon
Restart=always
User=$USER
# Note: Binding to port 53 requires CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF

    sudo systemctl daemon-reload
    sudo systemctl enable --now kinetic-daemon.service

    if systemctl is-active --quiet systemd-resolved; then
        echo "Configuring systemd-resolved OS DNS integration..."
        sudo mkdir -p /etc/systemd/resolved.conf.d/
        cat << EOF | sudo tee /etc/systemd/resolved.conf.d/kinetic.conf > /dev/null
[Resolve]
DNS=127.0.0.2
Domains=~kin
EOF
        sudo systemctl restart systemd-resolved
    else
        echo "WARNING: systemd-resolved is not active. You may need to manually configure your DNS resolver to point '.kin' requests to 127.0.0.2"
    fi

elif [ "$OS" = "Darwin" ]; then
    echo "Configuring macOS launchd service..."
    # Create the launch daemon for macOS
    cat << EOF | sudo tee /Library/LaunchDaemons/com.kinetic.daemon.plist > /dev/null
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

    # Load the daemon
    sudo launchctl unload -w /Library/LaunchDaemons/com.kinetic.daemon.plist 2>/dev/null || true
    sudo launchctl load -w /Library/LaunchDaemons/com.kinetic.daemon.plist

    # Configure macOS split DNS natively
    echo "Configuring macOS Split-DNS via /etc/resolver..."
    sudo mkdir -p /etc/resolver
    cat << EOF | sudo tee /etc/resolver/kin > /dev/null
nameserver 127.0.0.1
port 53
EOF
fi

echo "=== Kinetic is successfully installed and running! ==="
echo "You can now run 'kinetic-cli' to secure your names."
echo "You can access the Kinetic Dashboard at: http://localhost:16002"
echo "Documentation & Guide: https://saifmukhtar.github.io/kinetic/"
