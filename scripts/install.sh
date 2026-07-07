#!/bin/bash
set -e

# Hide cursor
tput civis
trap "tput cnorm" EXIT

# Colors
CYAN='\033[0;36m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

# Helper for arrow key menu
select_menu() {
    local prompt="$1" outvar="$2"
    shift 2
    local options=("$@") cur=0 count=${#options[@]}
    
    echo -e "${CYAN}======================================================${NC}"
    echo -e "${CYAN}      Kinetic Protocol Universal Installer${NC}"
    echo -e "${CYAN}======================================================${NC}"
    echo ""
    echo -e "$prompt"
    
    while true; do
        for ((i=0; i<count; i++)); do
            if [ $i -eq $cur ]; then
                echo -e "  ${GREEN}❯ \e[7m${options[$i]}\e[27m${NC}"
            else
                echo -e "    ${options[$i]}"
            fi
        done
        read -rsn1 key
        if [[ $key == $'\e' ]]; then
            read -rsn2 key
            if [[ $key == "[A" ]]; then # Up arrow
                ((cur--))
                ((cur < 0)) && cur=$((count-1))
            elif [[ $key == "[B" ]]; then # Down arrow
                ((cur++))
                ((cur >= count)) && cur=0
            fi
        elif [[ $key == "" ]]; then # Enter key
            break
        fi
        # Clear menu lines
        echo -en "\e[${count}A"
    done
    
    eval $outvar="'$cur'"
    echo ""
}

# 1. Detect OS
OS="$(uname -s)"
ARCH="$(uname -m)"
ASSET_SUFFIX=""
if [ "$OS" = "Linux" ]; then ASSET_SUFFIX="linux"
elif [ "$OS" = "Darwin" ]; then ASSET_SUFFIX="macos"
else echo "Unsupported OS"; exit 1; fi

# 2. Check existing
EXISTING_BINS=()
for bin in kinetic-daemon kinetic-node kinetic-host kinetic-dns-server kinetic-cli kinetic-keygen; do
    if [ -f "/usr/local/bin/$bin" ]; then EXISTING_BINS+=("$bin"); fi
done

if [ ${#EXISTING_BINS[@]} -gt 0 ]; then
    OPTIONS=("Upgrade / Change Profile" "Full Cleanup (Nuke everything)" "Exit")
    select_menu "Existing installation detected: ${EXISTING_BINS[*]}. Action:" CHOICE "${OPTIONS[@]}"
    
    if [ "$CHOICE" -eq 2 ]; then
        tput cnorm
        exit 0
    elif [ "$CHOICE" -eq 1 ]; then
        tput cnorm
        echo -e "${RED}!!! DANGER ZONE !!!${NC}"
        read -p "Type 'YES' to confirm full wipe (including identity keys): " CONFIRM
        if [ "$CONFIRM" = "YES" ]; then
            sudo -v
            for bin in "${EXISTING_BINS[@]}"; do
                sudo "/usr/local/bin/$bin" stop-service 2>/dev/null || true
                sudo "/usr/local/bin/$bin" uninstall 2>/dev/null || true
                sudo rm -f "/usr/local/bin/$bin"
            done
            rm -rf ~/.config/kinetic/
            echo "Cleanup complete."
            exit 0
        else exit 1; fi
    elif [ "$CHOICE" -eq 0 ]; then
        sudo -v
        for bin in "${EXISTING_BINS[@]}"; do
            sudo "/usr/local/bin/$bin" stop-service 2>/dev/null || true
            sudo "/usr/local/bin/$bin" uninstall 2>/dev/null || true
            sudo rm -f "/usr/local/bin/$bin"
        done
    fi
    clear
fi

OPTIONS=(
    "Standard User   (Daemon + CLI)"
    "Power User      (Daemon + CLI + DNS Server)"
    "Node Operator   (Node + CLI)"
    "Host Operator   (Host + CLI)"
    "Exit"
)
select_menu "Select Installation Profile:" PROFILE "${OPTIONS[@]}"

BINS_TO_INSTALL=("kinetic-cli")
INSTALL_DNS=false

case $PROFILE in
    0) BINS_TO_INSTALL+=("kinetic-daemon") ;;
    1) BINS_TO_INSTALL+=("kinetic-daemon" "kinetic-dns-server"); INSTALL_DNS=true ;;
    2) BINS_TO_INSTALL+=("kinetic-node") ;;
    3) BINS_TO_INSTALL+=("kinetic-host") ;;
    4) tput cnorm; exit 0 ;;
esac

tput cnorm
echo -e "${YELLOW}Installing: ${BINS_TO_INSTALL[*]}${NC}"
sudo -v

for bin in "${BINS_TO_INSTALL[@]}"; do
    echo "Downloading $bin..."
    curl -sL "https://github.com/saifmukhtar/kinetic/releases/latest/download/$bin-$ASSET_SUFFIX" -o "/tmp/$bin"
    sudo cp "/tmp/$bin" "/usr/local/bin/$bin"
    sudo chmod +x "/usr/local/bin/$bin"
    rm -f "/tmp/$bin"

    if [[ "$bin" != "kinetic-cli" ]]; then
        sudo "/usr/local/bin/$bin" install
        sudo "/usr/local/bin/$bin" start-service
    fi
done

if [ "$INSTALL_DNS" = true ]; then
    if [ "$OS" = "Linux" ] && systemctl is-active --quiet systemd-resolved; then
        sudo mkdir -p /etc/systemd/resolved.conf.d/
        cat << 'RES' | sudo tee /etc/systemd/resolved.conf.d/kinetic.conf > /dev/null
[Resolve]
DNS=127.0.0.2
Domains=~kin
RES
        sudo systemctl restart systemd-resolved
    elif [ "$OS" = "Darwin" ]; then
        sudo mkdir -p /etc/resolver
        cat << 'RES' | sudo tee /etc/resolver/kin > /dev/null
nameserver 127.0.0.1
port 53
RES
    fi
fi

echo -e "\n${GREEN}=== Kinetic installed successfully! ===${NC}"
