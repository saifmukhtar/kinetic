#!/bin/bash

# Kinetic Daemon Installer (Local PC)
set -e

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (e.g., sudo ./install-daemon.sh)"
  exit 1
fi

USER_NAME=$(logname || echo $SUDO_USER)
USER_HOME=$(eval echo ~$USER_NAME)

echo "Stopping any existing Kinetic services..."
systemctl stop kinetic-daemon.service 2>/dev/null || true
systemctl disable kinetic-daemon.service 2>/dev/null || true
systemctl stop kinetic-node.service 2>/dev/null || true
systemctl disable kinetic-node.service 2>/dev/null || true

echo "Removing old binaries and services..."
rm -f /etc/systemd/system/kinetic-daemon.service
rm -f /etc/systemd/system/kinetic-node.service
rm -f /usr/local/bin/kinetic-daemon
rm -f /usr/local/bin/kinetic-cli
rm -f /usr/local/bin/kinetic-node
systemctl daemon-reload

echo "Wiping existing local data and configurations..."
rm -rf "$USER_HOME/.config/kinetic"
rm -rf "$USER_HOME/.local/share/kinetic"
rm -rf "/root/.config/kinetic"
rm -rf "/root/.local/share/kinetic"

echo "Copying newly compiled binaries to /usr/local/bin..."
# Assuming we are in the source directory where `cargo build --release` was run
cp target/release/kinetic-daemon /usr/local/bin/
cp target/release/kinetic-cli /usr/local/bin/

echo "Creating systemd service for Kinetic Daemon..."
cat <<EOF > /etc/systemd/system/kinetic-daemon.service
[Unit]
Description=Kinetic Network Client Daemon
After=network.target

[Service]
Type=simple
User=$USER_NAME
Group=$USER_NAME
Environment="HOME=$USER_HOME"
Environment="RUST_LOG=info"
ExecStart=/usr/local/bin/kinetic-daemon
Restart=always
RestartSec=3
LimitNOFILE=65536
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF

echo "Reloading systemd and enabling Kinetic Daemon..."
systemctl daemon-reload
systemctl enable --now kinetic-daemon.service

echo "Installation complete!"
echo "Check status with: sudo systemctl status kinetic-daemon"
