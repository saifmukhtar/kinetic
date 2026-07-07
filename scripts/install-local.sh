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
    echo -e "${CYAN}    Kinetic Protocol Local Source Installer${NC}"
    echo -e "${CYAN}======================================================${NC}"
    echo "This script compiles Kinetic directly from source using Cargo."
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
        echo -en "\e[${count}A"
    done
    
    eval $outvar="'$cur'"
    echo ""
}

if ! command -v cargo &> /dev/null; then
    tput cnorm
    echo -e "${RED}Error: cargo could not be found. Please install Rust via https://rustup.rs${NC}"
    exit 1
fi

OPTIONS=(
    "Standard User   (Daemon + CLI)"
    "Power User      (Daemon + CLI + DNS Server)"
    "Node Operator   (Node + CLI)"
    "Host Operator   (Host + CLI)"
    "Exit"
)
select_menu "Select Installation Profile:" PROFILE "${OPTIONS[@]}"

BINS_TO_BUILD=("kinetic-cli")
INSTALL_DNS=false

case $PROFILE in
    0) BINS_TO_BUILD+=("kinetic-daemon") ;;
    1) BINS_TO_BUILD+=("kinetic-daemon" "kinetic-dns-server"); INSTALL_DNS=true ;;
    2) BINS_TO_BUILD+=("kinetic-node") ;;
    3) BINS_TO_BUILD+=("kinetic-host") ;;
    4) tput cnorm; exit 0 ;;
esac

tput cnorm
echo -e "${YELLOW}Building: ${BINS_TO_BUILD[*]}${NC}"
echo ""

CARGO_ARGS=()
for bin in "${BINS_TO_BUILD[@]}"; do
    CARGO_ARGS+=("-p" "$bin")
done

cd "$(dirname "$0")/.."
cargo build --release "${CARGO_ARGS[@]}"

echo -e "\n${GREEN}Compilation successful. Installing to /usr/local/bin...${NC}"
sudo -v

for bin in "${BINS_TO_BUILD[@]}"; do
    sudo cp "target/release/$bin" "/usr/local/bin/$bin"
    if [[ "$bin" != "kinetic-cli" ]]; then
        sudo "/usr/local/bin/$bin" stop-service 2>/dev/null || true
        sudo "/usr/local/bin/$bin" uninstall 2>/dev/null || true
        sudo "/usr/local/bin/$bin" install
        sudo "/usr/local/bin/$bin" start-service
    fi
done

OS="$(uname -s)"
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

echo -e "\n${GREEN}=== Kinetic successfully built and installed! ===${NC}"
echo -e "${CYAN}Documentation & Guide:${NC} https://kinetic.saifmukhtar.dev"
echo -e "${CYAN}Local Dashboard:${NC}       http://localhost:16002\n"
