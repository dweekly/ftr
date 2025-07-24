#!/bin/bash
# Create and configure Ubuntu VM in UTM for ftr testing

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ISO_DIR="$SCRIPT_DIR/iso-images"
UTMCTL="/Applications/UTM.app/Contents/MacOS/utmctl"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}=== Creating Ubuntu VM for ftr Testing ===${NC}"
echo

# Check for Ubuntu ISO
UBUNTU_ISO="$ISO_DIR/ubuntu-22.04.5-live-server-arm64.iso"
if [ ! -f "$UBUNTU_ISO" ]; then
    echo -e "${RED}Ubuntu ISO not found!${NC}"
    echo "Please run ./scripts/download-isos.sh first"
    exit 1
fi

echo -e "${GREEN}✓ Found Ubuntu ISO${NC}"

# Since UTM doesn't support full CLI VM creation, we'll open UTM with instructions
echo -e "${YELLOW}Opening UTM. Please create the VM with these settings:${NC}"
echo
echo "1. Click '+' to create new VM"
echo "2. Select 'Virtualize' (for ARM64 native)"
echo "3. Select 'Linux'"
echo "4. Click 'Browse' and select:"
echo "   $UBUNTU_ISO"
echo
echo "5. Configure VM settings:"
echo "   - Name: ftr-ubuntu"
echo "   - RAM: 4096 MB (4 GB)"
echo "   - CPU Cores: 4"
echo "   - Storage: 20 GB"
echo
echo "6. IMPORTANT - Network Configuration:"
echo "   - Go to Network settings"
echo "   - Change 'Network Mode' from 'Shared Network' to 'Bridged (Advanced)'"
echo "   - Bridged Interface: en0 (or your active network interface)"
echo
echo "7. Save and start the VM"
echo
echo -e "${BLUE}=== Ubuntu Installation Instructions ===${NC}"
echo
echo "During Ubuntu installation:"
echo "1. Choose 'Ubuntu Server' (not minimal)"
echo "2. Network should auto-configure via DHCP"
echo "3. User setup:"
echo "   - Your name: ftr"
echo "   - Server name: ftr-ubuntu"
echo "   - Username: ftr"
echo "   - Password: (your choice, remember it)"
echo
echo "4. Enable OpenSSH server when prompted"
echo
echo "5. After installation completes and VM reboots, note the IP address"
echo "   Run in VM: ip addr show"
echo
echo -e "${YELLOW}Press Enter to open UTM...${NC}"
read -r

# Open UTM
open -a UTM

# Create a post-install script
cat > "$SCRIPT_DIR/ubuntu-post-install.sh" <<'EOF'
#!/bin/bash
# Run this script inside the Ubuntu VM after installation

set -euo pipefail

echo "=== Ubuntu Post-Install Setup for ftr ==="
echo

# Update system
echo "Updating system packages..."
sudo apt update && sudo apt upgrade -y

# Install required packages
echo "Installing build dependencies..."
sudo apt install -y build-essential git curl libpcap-dev net-tools iputils-ping traceroute

# Install Rust
echo "Installing Rust..."
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"

# Clone ftr
echo "Cloning ftr repository..."
git clone https://github.com/dweekly/ftr
cd ftr

# Build ftr
echo "Building ftr..."
cargo build --release

# Test ftr
echo "Testing ftr..."
echo "Non-root test:"
./target/release/ftr google.com -m 5

echo
echo "Root test:"
sudo ./target/release/ftr google.com -m 5

echo
echo "=== Setup Complete! ==="
echo "ftr is ready for testing at: ~/ftr/target/release/ftr"
echo
echo "To add to PATH:"
echo "echo 'export PATH=\$PATH:~/ftr/target/release' >> ~/.bashrc"
echo "source ~/.bashrc"
EOF

chmod +x "$SCRIPT_DIR/ubuntu-post-install.sh"

echo
echo -e "${GREEN}Created post-install script: $SCRIPT_DIR/ubuntu-post-install.sh${NC}"
echo
echo "After VM installation and reboot:"
echo "1. Note the VM's IP address (run: ip addr show)"
echo "2. Copy the post-install script to the VM:"
echo "   scp $SCRIPT_DIR/ubuntu-post-install.sh ftr@<VM-IP>:~/"
echo "3. SSH into the VM:"
echo "   ssh ftr@<VM-IP>"
echo "4. Run the post-install script:"
echo "   ./ubuntu-post-install.sh"
echo
echo "Or manually run these commands in the VM:"
echo "   sudo apt update && sudo apt install -y build-essential git curl libpcap-dev"
echo "   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
echo "   git clone https://github.com/dweekly/ftr && cd ftr"
echo "   cargo build --release"