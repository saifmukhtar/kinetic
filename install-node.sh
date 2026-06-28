#!/bin/bash

# Kinetic Infrastructure Node Installation Script
# This script downloads the latest kinetic-node release and installs it as a systemd service.

set -e

REPO="saifmukhtar/kinetic"
BINARY_NAME="kinetic-node-linux"
INSTALL_PATH="/usr/local/bin/kinetic-node"
SERVICE_PATH="/etc/systemd/system/kinetic-node.service"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (e.g., sudo ./install-node.sh)"
  exit 1
fi

echo "Fetching latest release information..."
LATEST_RELEASE_URL=$(curl -s "https://api.github.com/repos/$REPO/releases/latest" | grep "browser_download_url.*$BINARY_NAME" | cut -d '"' -f 4)

if [ -z "$LATEST_RELEASE_URL" ]; then
    echo "Error: Could not find the latest release for $BINARY_NAME. Make sure a release exists."
    exit 1
fi

echo "Downloading $BINARY_NAME from $LATEST_RELEASE_URL..."
curl -L -o /tmp/$BINARY_NAME "$LATEST_RELEASE_URL"

echo "Installing binary to $INSTALL_PATH..."
chmod +x /tmp/$BINARY_NAME
mv /tmp/$BINARY_NAME $INSTALL_PATH

echo "Creating systemd service at $SERVICE_PATH..."
cat <<EOF > $SERVICE_PATH
[Unit]
Description=Kinetic Network Infrastructure Node
After=network.target

[Service]
Type=simple
# We run as root, but ideally you should create a kinetic user. For AWS deployment, root is often used initially.
# User=root
ExecStart=$INSTALL_PATH
Restart=always
RestartSec=3
Environment="RUST_LOG=info"
# Implicitly triggers infrastructure node configuration
Environment="KINETIC_STATIC_NODE=1"
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

echo "Reloading systemd daemon..."
systemctl daemon-reload

echo "Enabling and starting kinetic-node service..."
systemctl enable --now kinetic-node.service

echo ""
echo "Installation complete!"
echo "Check the service status with: sudo systemctl status kinetic-node"
echo "View logs with: sudo journalctl -u kinetic-node -f"
echo "Check the static Peer ID: curl -s http://localhost:16003/peer_id"
