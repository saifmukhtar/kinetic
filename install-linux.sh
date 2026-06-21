#!/bin/bash
set -e

echo "=== Kinetic Daemon Installer (Linux) ==="

# 1. Download the latest binary (Assuming standard x86_64 linux)
# In production, this would hit the GitHub Releases API
echo "Downloading Kinetic Daemon..."
curl -L https://github.com/saifmukhtar/kinetic/releases/latest/download/kinetic-daemon-linux -o /tmp/kinetic-daemon
sudo mv /tmp/kinetic-daemon /usr/local/bin/kinetic-daemon
sudo chmod +x /usr/local/bin/kinetic-daemon

# 2. Setup systemd service
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

# 3. Setup systemd-resolved to use 127.0.0.1:53 exclusively for .kin domains
echo "Configuring OS DNS integration..."
sudo mkdir -p /etc/systemd/resolved.conf.d/
cat << EOF | sudo tee /etc/systemd/resolved.conf.d/kinetic.conf > /dev/null
[Resolve]
DNS=127.0.0.1
Domains=~kin
EOF

sudo systemctl restart systemd-resolved

echo "=== Kinetic is installed and running! ==="
echo "Try visiting http://anyname.kin in your browser."
