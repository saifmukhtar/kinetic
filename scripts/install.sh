#!/bin/bash
set -e

echo "======================================================"
echo "      Kinetic Protocol Universal Installer"
echo "======================================================"
echo ""

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
echo ""

# 2. Check for existing installation
EXISTING_BINS=()
for bin in kinetic-daemon kinetic-node kinetic-host kinetic-dns-server kinetic-cli kinetic-keygen; do
    if [ -f "/usr/local/bin/$bin" ]; then
        EXISTING_BINS+=("$bin")
    fi
done

if [ ${#EXISTING_BINS[@]} -gt 0 ]; then
    echo "Existing Kinetic installation detected: ${EXISTING_BINS[*]}"
    echo ""
    echo "Please select an action:"
    echo "1) Upgrade / Change Profile (removes old binaries and replaces them)"
    echo "2) Full Cleanup (Nuke) (WARNING: removes everything INCLUDING your identity keys)"
    echo "3) Exit"
    read -p "Selection [1-3]: " UPGRADE_CHOICE

    if [ "$UPGRADE_CHOICE" = "3" ]; then
        echo "Exiting."
        exit 0
    elif [ "$UPGRADE_CHOICE" = "2" ]; then
        echo ""
        echo "!!! DANGER ZONE !!!"
        echo "This will permanently delete your node identity, DNS keys, and all local storage."
        read -p "Type 'YES' to confirm full cleanup: " CONFIRM_WIPE
        if [ "$CONFIRM_WIPE" = "YES" ]; then
            echo "Stopping and uninstalling services..."
            for bin in kinetic-daemon kinetic-node kinetic-host kinetic-dns-server; do
                if [ -f "/usr/local/bin/$bin" ]; then
                    sudo "/usr/local/bin/$bin" stop-service 2>/dev/null || true
                    sudo "/usr/local/bin/$bin" uninstall 2>/dev/null || true
                    sudo rm -f "/usr/local/bin/$bin"
                fi
            done
            sudo rm -f /usr/local/bin/kinetic-cli /usr/local/bin/kinetic-keygen
            
            # Clean OS-level DNS integration if exists
            if [ "$OS" = "Linux" ]; then
                sudo rm -f /etc/systemd/resolved.conf.d/kinetic.conf
                sudo systemctl restart systemd-resolved || true
            elif [ "$OS" = "Darwin" ]; then
                sudo rm -f /etc/resolver/kin
            fi

            # Clean identity storage
            rm -rf ~/.config/kinetic/
            echo "Full cleanup completed."
            exit 0
        else
            echo "Confirmation failed. Exiting."
            exit 1
        fi
    elif [ "$UPGRADE_CHOICE" = "1" ]; then
        echo "Stopping services before upgrade..."
        for bin in kinetic-daemon kinetic-node kinetic-host kinetic-dns-server; do
            if [ -f "/usr/local/bin/$bin" ]; then
                sudo "/usr/local/bin/$bin" stop-service 2>/dev/null || true
                sudo "/usr/local/bin/$bin" uninstall 2>/dev/null || true
                sudo rm -f "/usr/local/bin/$bin"
            fi
        done
        sudo rm -f /usr/local/bin/kinetic-cli /usr/local/bin/kinetic-keygen
    else
        echo "Invalid choice. Exiting."
        exit 1
    fi
fi

echo "======================================================"
echo "      Select Installation Profile"
echo "======================================================"
echo "1) Standard User  (Daemon + CLI)"
echo "   -> For regular users wanting to resolve and register .kin domains safely."
echo "2) Power User     (Daemon + CLI + DNS Server)"
echo "   -> For advanced users wanting OS-level DNS integration (e.g., Pi-hole compatibility)."
echo "3) Node Operator  (Node + CLI)"
echo "   -> For infrastructure providers running P2P bootstrap nodes."
echo "4) Host Operator  (Host + CLI)"
echo "   -> For users hosting content or web services on a VPS."
echo "5) Advanced       (Custom Selection)"
echo "6) Exit"
echo "======================================================"
read -p "Profile Selection [1-6]: " PROFILE_CHOICE

BINS_TO_INSTALL=("kinetic-cli")
INSTALL_DNS_INTEGRATION=false

case "$PROFILE_CHOICE" in
    1)
        BINS_TO_INSTALL+=("kinetic-daemon")
        ;;
    2)
        BINS_TO_INSTALL+=("kinetic-daemon" "kinetic-dns-server")
        INSTALL_DNS_INTEGRATION=true
        ;;
    3)
        BINS_TO_INSTALL+=("kinetic-node")
        ;;
    4)
        BINS_TO_INSTALL+=("kinetic-host")
        ;;
    5)
        echo ""
        echo "Advanced Selection (CLI is always installed):"
        read -p "Install Daemon? (y/N): " ADV_DAEMON
        read -p "Install Node? (y/N): " ADV_NODE
        read -p "Install Host? (y/N): " ADV_HOST
        read -p "Install Keygen? (y/N): " ADV_KEYGEN
        read -p "Install DNS Server? (y/N): " ADV_DNS

        [[ "$ADV_DAEMON" =~ ^[Yy]$ ]] && BINS_TO_INSTALL+=("kinetic-daemon")
        [[ "$ADV_NODE" =~ ^[Yy]$ ]] && BINS_TO_INSTALL+=("kinetic-node")
        [[ "$ADV_HOST" =~ ^[Yy]$ ]] && BINS_TO_INSTALL+=("kinetic-host")
        [[ "$ADV_KEYGEN" =~ ^[Yy]$ ]] && BINS_TO_INSTALL+=("kinetic-keygen")
        if [[ "$ADV_DNS" =~ ^[Yy]$ ]]; then
            BINS_TO_INSTALL+=("kinetic-dns-server")
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
echo "The following binaries will be installed: ${BINS_TO_INSTALL[*]}"
echo "OS-level DNS integration enabled: $INSTALL_DNS_INTEGRATION"
echo ""

# Ensure sudo is authenticated early
sudo -v

for bin in "${BINS_TO_INSTALL[@]}"; do
    echo "Downloading $bin..."
    curl -sL "https://github.com/saifmukhtar/kinetic/releases/latest/download/$bin-$ASSET_SUFFIX" -o "/tmp/$bin"
    sudo cp "/tmp/$bin" "/usr/local/bin/$bin"
    sudo chmod +x "/usr/local/bin/$bin"
    rm -f "/tmp/$bin"

    # If it's a long running service, install and start it using the native command
    if [[ "$bin" != "kinetic-cli" && "$bin" != "kinetic-keygen" ]]; then
        echo "Installing system service for $bin..."
        sudo "/usr/local/bin/$bin" install
        sudo "/usr/local/bin/$bin" start-service
    fi
done

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
        else
            echo "WARNING: systemd-resolved is not active. You may need to manually configure your DNS resolver to point '.kin' requests to 127.0.0.2"
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
echo "=== Kinetic is successfully installed and running! ==="
echo "You can now run 'kinetic-cli' to manage your identity."
echo "Documentation & Guide: https://saifmukhtar.github.io/kinetic/"
