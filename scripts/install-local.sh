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

# Print branding banner
print_banner() {
    echo -e "${CYAN}   _  _____ _   _ _____ _____ ___ ____ ${NC}"
    echo -e "${CYAN}  | |/ /_ _| \ | | ____|_   _|_ _/ ___|${NC}"
    echo -e "${CYAN}  | ' / | ||  \| |  _|   | |  | | |    ${NC}"
    echo -e "${CYAN}  | . \ | || |\  | |___  | |  | | |___ ${NC}"
    echo -e "${CYAN}  |_|\_\___|_| \_|_____| |_| |___\____|${NC}"
    echo ""
    echo -e "${GREEN}  Welcome to the Kinetic Local Source Installer!${NC}"
    echo -e "${YELLOW}  Compiling from source using Cargo.${NC}"
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

if ! command -v cargo &> /dev/null; then
    tput cnorm
    echo -e "${RED}Error: cargo could not be found. Please install Rust via https://rustup.rs${NC}"
    exit 1
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

BINS_TO_BUILD=("kinetic-cli")
INSTALL_DNS=false

case $PROFILE in
    0) BINS_TO_BUILD+=("kinetic-daemon") ;;
    1) BINS_TO_BUILD+=("kinetic-daemon" "kinetic-dns-server"); INSTALL_DNS=true ;;
    2) BINS_TO_BUILD+=("kinetic-node") ;;
    3) BINS_TO_BUILD+=("kinetic-host") ;;
    4) 
        clear
        MENU_OPTIONS=("kinetic-daemon" "kinetic-dns-server" "kinetic-node" "kinetic-host")
        MENU_DESCRIPTIONS=(
            "Runs the VDF and P2P client for .kin resolution."
            "System-wide DNS server for local OS integration."
            "P2P bootstrap node for infrastructure providers."
            "Content hosting server for static files and web services."
        )
        select_multi_menu "Select components to install (Space to toggle, Enter to confirm):" CUSTOM_OPTS
        for opt in $CUSTOM_OPTS; do
            if [ "$opt" -eq 0 ]; then BINS_TO_BUILD+=("kinetic-daemon"); fi
            if [ "$opt" -eq 1 ]; then BINS_TO_BUILD+=("kinetic-dns-server"); INSTALL_DNS=true; fi
            if [ "$opt" -eq 2 ]; then BINS_TO_BUILD+=("kinetic-node"); fi
            if [ "$opt" -eq 3 ]; then BINS_TO_BUILD+=("kinetic-host"); fi
        done
        ;;
    5) tput cnorm; exit 0 ;;
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
if [[ " ${BINS_TO_BUILD[*]} " =~ " kinetic-daemon " ]]; then
    echo -e "${CYAN}Local Dashboard:${NC}       http://localhost:16002\n"
else
    echo ""
fi
