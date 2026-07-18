#!/bin/bash
set -e

# Hide cursor
tput civis

# Colors
CYAN='\033[0;36m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

# Print branding banner
print_banner() {
    echo -e "${CYAN}   _  _____ _   _ _____ _____ ___ ____ ${NC}"
    echo -e "${CYAN}  | |/ /_ _| \ | | ____|_   _|_ _/ ___|${NC}"
    echo -e "${CYAN}  | ' / | ||  \| |  _|   | |  | | |    ${NC}"
    echo -e "${CYAN}  | . \ | || |\  | |___  | |  | | |___ ${NC}"
    echo -e "${CYAN}  |_|\_\___|_| \_|_____| |_| |___\____|${NC}"
    echo ""
    echo -e "${GREEN}  Welcome to the Kinetic Protocol Installer!${NC}"
    echo -e "${YELLOW}  Setup your node, daemon, and DNS natively.${NC}"
    echo ""
}

# Helper for arrow key menu
select_menu() {
    local prompt="$1" outvar="$2"
    local count=${#MENU_OPTIONS[@]}
    local cur=0 
    
    print_banner
    echo -e "$prompt\n"
    
    while true; do
        for ((i=0; i<count; i++)); do
            if [ $i -eq $cur ]; then
                echo -e "  ${GREEN}❯ \e[7m${MENU_OPTIONS[$i]}\e[27m${NC}"
            else
                echo -e "    ${MENU_OPTIONS[$i]}"
            fi
        done
        
        echo ""
        if [ ${#MENU_DESCRIPTIONS[@]} -gt 0 ]; then
            echo -e "  ${YELLOW}ℹ ${MENU_DESCRIPTIONS[$cur]}${NC}"
        else
            echo ""
        fi
        
        IFS= read -rsn1 key
        if [[ $key == $'\e' ]]; then
            read -rsn2 -t 0.1 key
            if [[ $key == "[A" ]]; then # Up arrow
                ((cur--)) || true
                if (( cur < 0 )); then cur=$((count-1)); fi
            elif [[ $key == "[B" ]]; then # Down arrow
                ((cur++)) || true
                if (( cur >= count )); then cur=0; fi
            fi
        elif [[ $key == "" ]]; then # Enter key
            break
        fi
        
        # Clear menu lines + description lines
        local clear_lines=$((count + 2))
        echo -en "\e[${clear_lines}A\e[J"
    done
    
    eval $outvar="'$cur'"
    echo ""
}

# Helper for multi-select menu
select_multi_menu() {
    local prompt="$1" outvar="$2"
    local count=${#MENU_OPTIONS[@]}
    local cur=0 
    local selected=()
    for ((i=0; i<count; i++)); do selected[$i]=0; done
    
    print_banner
    echo -e "$prompt\n"
    
    while true; do
        for ((i=0; i<count; i++)); do
            local checkbox="[ ]"
            if [ ${selected[$i]} -eq 1 ]; then
                checkbox="[x]"
            fi
            
            if [ $i -eq $cur ]; then
                echo -e "  ${GREEN}❯ \e[7m${checkbox} ${MENU_OPTIONS[$i]}\e[27m${NC}"
            else
                echo -e "    ${checkbox} ${MENU_OPTIONS[$i]}"
            fi
        done
        
        echo ""
        if [ ${#MENU_DESCRIPTIONS[@]} -gt 0 ]; then
            echo -e "  ${YELLOW}ℹ ${MENU_DESCRIPTIONS[$cur]}${NC}"
        else
            echo ""
        fi
        
        IFS= read -rsn1 key
        if [[ $key == $'\e' ]]; then
            read -rsn2 -t 0.1 key
            if [[ $key == "[A" ]]; then # Up arrow
                ((cur--)) || true
                if (( cur < 0 )); then cur=$((count-1)); fi
            elif [[ $key == "[B" ]]; then # Down arrow
                ((cur++)) || true
                if (( cur >= count )); then cur=0; fi
            fi
        elif [[ $key == " " ]]; then # Space key
            if [ ${selected[$cur]} -eq 1 ]; then
                selected[$cur]=0
            else
                selected[$cur]=1
            fi
        elif [[ $key == "" ]]; then # Enter key
            break
        fi
        
        local clear_lines=$((count + 2))
        echo -en "\e[${clear_lines}A\e[J"
    done
    
    local result=""
    for ((i=0; i<count; i++)); do
        if [ ${selected[$i]} -eq 1 ]; then
            result="$result $i"
        fi
    done
    eval $outvar="'$result'"
    echo ""
}

# 1. Detect OS
OS="$(uname -s)"
ARCH="$(uname -m)"
ASSET_SUFFIX=""
CHECKSUM_FILE=""
if [ "$OS" = "Linux" ]; then 
    ASSET_SUFFIX="linux"
    CHECKSUM_FILE="checksums-ubuntu-latest.txt"
elif [ "$OS" = "Darwin" ]; then 
    ASSET_SUFFIX="macos"
    CHECKSUM_FILE="checksums-macos-latest.txt"
else 
    echo "Unsupported OS"; exit 1; 
fi

# 2. Check existing
EXISTING_BINS=()
for bin in kinetic-daemon kinetic-node kinetic-host kinetic-dns kinetic kinetic-keygen; do
    if [ -f "/usr/local/bin/$bin" ]; then EXISTING_BINS+=("$bin"); fi
done

if [ ${#EXISTING_BINS[@]} -gt 0 ]; then
    MENU_OPTIONS=("Upgrade / Change Profile" "Full Cleanup (Nuke everything)" "Exit")
    MENU_DESCRIPTIONS=()
    select_menu "Existing installation detected: ${EXISTING_BINS[*]}. Action:" CHOICE
    
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
                sudo "/usr/local/bin/$bin" stop 2>/dev/null || true
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
            sudo "/usr/local/bin/$bin" stop 2>/dev/null || true
            sudo "/usr/local/bin/$bin" uninstall 2>/dev/null || true
            sudo rm -f "/usr/local/bin/$bin"
        done
    fi
    clear
fi

MENU_OPTIONS=(
    "Standard User   (Daemon + CLI)"
    "Power User      (Daemon + CLI + DNS Server)"
    "Node Operator   (Node + CLI)"
    "Host Operator   (Host + CLI)"
    "Custom / Adv.   (Choose components)"
    "Exit"
)
MENU_DESCRIPTIONS=(
    "For regular users wanting to resolve and register .kin domains safely."
    "For advanced users wanting OS-level DNS integration (e.g., Pi-hole compatibility)."
    "For infrastructure providers running P2P bootstrap nodes."
    "For users hosting content or web services on a VPS."
    "Manually select which Kinetic components you want to install."
    "Exit the installer without making changes."
)
select_menu "Select Installation Profile:" PROFILE

BINS_TO_INSTALL=("kinetic")
INSTALL_DNS=false

case $PROFILE in
    0) BINS_TO_INSTALL+=("kinetic-daemon") ;;
    1) BINS_TO_INSTALL+=("kinetic-daemon" "kinetic-dns"); INSTALL_DNS=true ;;
    2) BINS_TO_INSTALL+=("kinetic-node") ;;
    3) BINS_TO_INSTALL+=("kinetic-host") ;;
    4) 
        clear
        MENU_OPTIONS=("kinetic-daemon" "kinetic-dns" "kinetic-node" "kinetic-host")
        MENU_DESCRIPTIONS=(
            "Runs the VDF and P2P client for .kin resolution."
            "System-wide DNS server for local OS integration."
            "P2P bootstrap node for infrastructure providers."
            "Content hosting server for static files and web services."
        )
        select_multi_menu "Select components to install (Space to toggle, Enter to confirm):" CUSTOM_OPTS
        for opt in $CUSTOM_OPTS; do
            if [ "$opt" -eq 0 ]; then BINS_TO_INSTALL+=("kinetic-daemon"); fi
            if [ "$opt" -eq 1 ]; then BINS_TO_INSTALL+=("kinetic-dns"); INSTALL_DNS=true; fi
            if [ "$opt" -eq 2 ]; then BINS_TO_INSTALL+=("kinetic-node"); fi
            if [ "$opt" -eq 3 ]; then BINS_TO_INSTALL+=("kinetic-host"); fi
        done
        ;;
    5) tput cnorm; exit 0 ;;
esac

tput cnorm
echo -e "${YELLOW}Installing: ${BINS_TO_INSTALL[*]}${NC}"
sudo -v

TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"; tput cnorm' EXIT

echo "Downloading checksums..."
curl -sL "https://github.com/saifmukhtar/kinetic/releases/latest/download/$CHECKSUM_FILE" -o "$TMP_DIR/checksums.txt"

for bin in "${BINS_TO_INSTALL[@]}"; do
    echo "Downloading $bin..."
    curl -sL "https://github.com/saifmukhtar/kinetic/releases/latest/download/$bin-$ASSET_SUFFIX" -o "$TMP_DIR/$bin-$ASSET_SUFFIX"

    echo "Verifying checksum for $bin..."
    if command -v sha256sum >/dev/null 2>&1; then
        grep "$bin-$ASSET_SUFFIX" "$TMP_DIR/checksums.txt" | (cd "$TMP_DIR" && sha256sum -c -)
    else
        grep "$bin-$ASSET_SUFFIX" "$TMP_DIR/checksums.txt" | (cd "$TMP_DIR" && shasum -a 256 -c -)
    fi

    sudo mv "$TMP_DIR/$bin-$ASSET_SUFFIX" "/usr/local/bin/$bin"
    sudo chown root:root "/usr/local/bin/$bin"
    sudo chmod 755 "/usr/local/bin/$bin"

    if [[ "$bin" != "kinetic" ]]; then
        sudo "/usr/local/bin/$bin" install
        sudo "/usr/local/bin/$bin" start
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
echo -e "${CYAN}Documentation & Guide:${NC} https://kinetic.saifmukhtar.dev"
echo ""
