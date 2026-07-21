#!/bin/bash
set -e

# Hide cursor safely
tput civis
trap 'tput cnorm' EXIT

# Colors
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${CYAN}=== Kinetic Dev Installer (Repro Mode) ===${NC}\n"

# 1. Handle Local Data Directory
REAL_USER="${SUDO_USER:-$USER}"
REAL_HOME=$(getent passwd "$REAL_USER" | cut -d: -f6)
SHARE_DIR="$REAL_HOME/.local/share/kinetic"
if [ -d "$SHARE_DIR" ]; then
    if [ -f "$SHARE_DIR/identity.key" ]; then
        echo -e "${YELLOW}Backing up identity.key to /tmp/identity.key.bak...${NC}"
        # Copy with permissions preserved
        cp -p "$SHARE_DIR/identity.key" "/tmp/identity.key.bak"
    fi
    echo -e "${YELLOW}Wiping $SHARE_DIR...${NC}"
    rm -rf "$SHARE_DIR"
fi

# 2. Discover existing binaries
EXISTING_BINS=()
for bin_path in /usr/local/bin/kinetic*; do
    if [ -f "$bin_path" ]; then
        bin=$(basename "$bin_path")
        EXISTING_BINS+=("$bin")
    fi
done

if [ ${#EXISTING_BINS[@]} -eq 0 ]; then
    echo -e "${YELLOW}No existing Kinetic binaries found in /usr/local/bin.${NC}"
    echo "This script is designed to reproduce an existing installation."
    exit 0
fi

echo -e "${GREEN}Remembered existing binaries:${NC} ${EXISTING_BINS[*]}"
echo ""

# Export HOME so that binaries run by this script (as root) will correctly locate 
# the user's ~/.local/share directory instead of /root/.local/share.
export HOME="$REAL_HOME"

# 3. Clean existing binaries
echo -e "${YELLOW}Stopping and uninstalling old binaries...${NC}"
for bin in "${EXISTING_BINS[@]}"; do
    # Only stop/uninstall services (not standard CLI apps)
    if [[ "$bin" != "kinetic" && "$bin" != "kinetic-cli" && "$bin" != "kinetic-keygen" ]]; then
        "/usr/local/bin/$bin" stop 2>/dev/null || true
        "/usr/local/bin/$bin" uninstall 2>/dev/null || true
    fi
    rm -f "/usr/local/bin/$bin"
done

# 4. Copy newly compiled binaries
echo -e "${YELLOW}Copying fresh binaries from target/release/...${NC}"
for bin in "${EXISTING_BINS[@]}"; do
    if [ -f "target/release/$bin" ]; then
        cp "target/release/$bin" "/usr/local/bin/$bin"
        chown root:root "/usr/local/bin/$bin"
        chmod 755 "/usr/local/bin/$bin"
        echo "  Copied $bin -> /usr/local/bin/$bin"
    else
        echo -e "${RED}  Warning: target/release/$bin not found! Ensure workspace is compiled.${NC}"
    fi
done

# 5. Restore or generate identity BEFORE starting services
echo -e "${YELLOW}\nRestoring identity.key...${NC}"
mkdir -p "$SHARE_DIR"
chown "$REAL_USER":"$REAL_USER" "$SHARE_DIR"

if [ -f "/tmp/identity.key.bak" ]; then
    echo "  Found backup. Restoring..."
    mv "/tmp/identity.key.bak" "$SHARE_DIR/identity.key"
    chown "$REAL_USER":"$REAL_USER" "$SHARE_DIR/identity.key"
else
    echo "  No backup found. Automatically generating a new identity for dev..."
    # Generate identity as REAL_USER to ensure proper permissions
    su - "$REAL_USER" -c "/usr/local/bin/kinetic setup" || true
fi

# 6. Install and Start services (Simulating exactly like install.sh)
echo -e "${YELLOW}\nInstalling and starting services...${NC}"
for bin in "${EXISTING_BINS[@]}"; do
    if [[ "$bin" != "kinetic" && "$bin" != "kinetic-cli" && "$bin" != "kinetic-keygen" ]]; then
        if [ -f "/usr/local/bin/$bin" ]; then
            echo "  Installing $bin..."
            "/usr/local/bin/$bin" install
            echo "  Starting $bin..."
            "/usr/local/bin/$bin" start
        fi
    fi
done

# 6. Fix permissions for the data directory
echo -e "${YELLOW}Fixing data directory permissions...${NC}"
chown -R "$REAL_USER":"$REAL_USER" "$SHARE_DIR"

echo -e "\n${GREEN}=== Dev Installation Reproduction Complete! ===${NC}"
