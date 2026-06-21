#!/bin/bash
set -e

echo "Building Kinetic Decentralized DNS from source..."
cargo build --release

echo "Installing binaries to /usr/local/bin..."
sudo cp target/release/kinetic-daemon /usr/local/bin/
sudo cp target/release/kinetic-cli /usr/local/bin/
sudo chmod +x /usr/local/bin/kinetic-*

echo "Creating config directory..."
mkdir -p ~/.kinetic
if [ ! -f ~/.kinetic/config.toml ]; then
    cat <<EOF > ~/.kinetic/config.toml
[daemon]
api_port = 6001
dns_port = 53
storage_dir = "$HOME/.kinetic/db"

[network]
p2p_port = 6070
bootstrap_nodes = []
EOF
    echo "Created default config at ~/.kinetic/config.toml"
fi

echo "Installing systemd service..."
sudo cp install/kinetic-daemon.service /etc/systemd/system/
sudo systemctl daemon-reload
# sudo systemctl enable kinetic-daemon.service
# sudo systemctl start kinetic-daemon.service

echo "=========================================="
echo "Kinetic installed successfully! 🎉"
echo "To start the daemon on boot: sudo systemctl enable --now kinetic-daemon.service"
echo "To check daemon logs: journalctl -fu kinetic-daemon"
echo "=========================================="
