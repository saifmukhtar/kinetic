#!/bin/bash
set -e

echo "======================================================"
echo "    Kinetic Protocol Local Source Installer"
echo "======================================================"
echo "This script compiles Kinetic directly from source using Cargo."
echo "Ensure you have the Rust toolchain installed (rustup)."
echo ""

if ! command -v cargo &> /dev/null; then
    echo "Error: cargo could not be found. Please install Rust via https://rustup.rs"
    exit 1
fi

echo "======================================================"
echo "      Select Installation Profile"
echo "======================================================"
echo "1) Standard User  (Daemon + CLI)"
echo "2) Power User     (Daemon + CLI + DNS Server)"
echo "3) Node Operator  (Node + CLI)"
echo "4) Host Operator  (Host + CLI)"
echo "5) Advanced       (Custom Selection)"
echo "6) Exit"
echo "======================================================"
read -p "Profile Selection [1-6]: " PROFILE_CHOICE

BINS_TO_BUILD=("kinetic-cli")
INSTALL_DNS_INTEGRATION=false

case "$PROFILE_CHOICE" in
    1)
        BINS_TO_BUILD+=("kinetic-daemon")
        ;;
    2)
        BINS_TO_BUILD+=("kinetic-daemon" "kinetic-dns-server")
        INSTALL_DNS_INTEGRATION=true
        ;;
    3)
        BINS_TO_BUILD+=("kinetic-node")
        ;;
    4)
        BINS_TO_BUILD+=("kinetic-host")
        ;;
    5)
        echo ""
        echo "Advanced Selection (CLI is always installed):"
        read -p "Install Daemon? (y/N): " ADV_DAEMON
        read -p "Install Node? (y/N): " ADV_NODE
        read -p "Install Host? (y/N): " ADV_HOST
        read -p "Install Keygen? (y/N): " ADV_KEYGEN
        read -p "Install DNS Server? (y/N): " ADV_DNS

        [[ "$ADV_DAEMON" =~ ^[Yy]$ ]] && BINS_TO_BUILD+=("kinetic-daemon")
        [[ "$ADV_NODE" =~ ^[Yy]$ ]] && BINS_TO_BUILD+=("kinetic-node")
        [[ "$ADV_HOST" =~ ^[Yy]$ ]] && BINS_TO_BUILD+=("kinetic-host")
        [[ "$ADV_KEYGEN" =~ ^[Yy]$ ]] && BINS_TO_BUILD+=("kinetic-keygen")
        if [[ "$ADV_DNS" =~ ^[Yy]$ ]]; then
            BINS_TO_BUILD+=("kinetic-dns-server")
            read -p "Enable OS-level DNS Integration? (y/N): " ADV_DNS_INT
            [[ "$ADV_DNS_INT" =~ ^[Yy]$ ]] && INSTALL_DNS_INTEGRATION=true
        fi
        ;;
    6)
        echo "Exiting."
        exit 0
        ;;
    *)
        echo "Invalid choice. Exiting."
        exit 1
        ;;
esac

echo ""
echo "Building the following binaries: ${BINS_TO_BUILD[*]}"
echo ""

# Build args
CARGO_ARGS=()
for bin in "${BINS_TO_BUILD[@]}"; do
    CARGO_ARGS+=("-p" "$bin")
done

# Navigate to repo root
cd "$(dirname "$0")/.."

echo "Running: cargo build --release ${CARGO_ARGS[*]}"
cargo build --release "${CARGO_ARGS[@]}"

echo ""
echo "Compilation successful. Installing to /usr/local/bin..."

sudo -v

for bin in "${BINS_TO_BUILD[@]}"; do
    sudo cp "target/release/$bin" "/usr/local/bin/$bin"
    
    # If it's a long running service, install and start it using the native command
    if [[ "$bin" != "kinetic-cli" && "$bin" != "kinetic-keygen" ]]; then
        echo "Installing system service for $bin..."
        sudo "/usr/local/bin/$bin" stop-service 2>/dev/null || true
        sudo "/usr/local/bin/$bin" uninstall 2>/dev/null || true
        sudo "/usr/local/bin/$bin" install
        sudo "/usr/local/bin/$bin" start-service
    fi
done

OS="$(uname -s)"
if [ "$INSTALL_DNS_INTEGRATION" = true ]; then
    if [ "$OS" = "Linux" ]; then
        if systemctl is-active --quiet systemd-resolved; then
            echo "Configuring systemd-resolved OS DNS integration..."
            sudo mkdir -p /etc/systemd/resolved.conf.d/
            cat << EOF | sudo tee /etc/systemd/resolved.conf.d/kinetic.conf > /dev/null
[Resolve]
DNS=127.0.0.2
Domains=~kin
EOF
            sudo systemctl restart systemd-resolved
        fi
    elif [ "$OS" = "Darwin" ]; then
        echo "Configuring macOS Split-DNS via /etc/resolver..."
        sudo mkdir -p /etc/resolver
        cat << EOF | sudo tee /etc/resolver/kin > /dev/null
nameserver 127.0.0.1
port 53
EOF
    fi
fi

echo ""
echo "=== Kinetic is successfully built and installed from source! ==="
