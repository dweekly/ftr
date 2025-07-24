#!/bin/bash
# Setup UTM VMs for cross-platform ftr testing

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo "=== UTM VM Setup for ftr Testing ==="
echo

# Check for UTM
UTMCTL="/Applications/UTM.app/Contents/MacOS/utmctl"
if [ ! -x "$UTMCTL" ]; then
    echo -e "${RED}Error: UTM not found${NC}"
    echo "Please install UTM from https://mac.getutm.app/"
    exit 1
fi

# Create VM configurations directory
mkdir -p "$SCRIPT_DIR/utm-configs"

# Function to create Ubuntu VM config
create_ubuntu_config() {
    cat > "$SCRIPT_DIR/utm-configs/ubuntu-config.json" <<'EOF'
{
  "name": "ftr-ubuntu",
  "architecture": "aarch64",
  "memory": 4096,
  "cpuCount": 4,
  "drives": [{
    "size": 20480,
    "interface": "virtio"
  }],
  "network": [{
    "mode": "bridged",
    "interface": "en0"
  }],
  "displays": [{
    "width": 1920,
    "height": 1080
  }]
}
EOF
}

# Function to create FreeBSD VM config
create_freebsd_config() {
    cat > "$SCRIPT_DIR/utm-configs/freebsd-config.json" <<'EOF'
{
  "name": "ftr-freebsd",
  "architecture": "aarch64",
  "memory": 4096,
  "cpuCount": 4,
  "drives": [{
    "size": 20480,
    "interface": "virtio"
  }],
  "network": [{
    "mode": "bridged",
    "interface": "en0"
  }],
  "displays": [{
    "width": 1920,
    "height": 1080
  }]
}
EOF
}

# Function to create Windows VM config (x86_64 emulation required)
create_windows_config() {
    cat > "$SCRIPT_DIR/utm-configs/windows-config.json" <<'EOF'
{
  "name": "ftr-windows",
  "architecture": "x86_64",
  "memory": 8192,
  "cpuCount": 4,
  "drives": [{
    "size": 61440,
    "interface": "virtio"
  }],
  "network": [{
    "mode": "bridged",
    "interface": "en0"
  }],
  "displays": [{
    "width": 1920,
    "height": 1080
  }]
}
EOF
}

# Create cloud-init configuration for Ubuntu
create_ubuntu_cloud_init() {
    mkdir -p "$SCRIPT_DIR/cloud-init"
    
    # Get the SSH public key
    SSH_KEY=$(cat ~/.ssh/ftr-test-key.pub 2>/dev/null || echo "NO_KEY_FOUND")
    
    # User data
    cat > "$SCRIPT_DIR/cloud-init/user-data" <<EOF
#cloud-config
users:
  - name: ftr
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    ssh_authorized_keys:
      - $SSH_KEY

packages:
  - build-essential
  - git
  - curl
  - libpcap-dev
  - net-tools
  - iputils-ping
  - traceroute

runcmd:
  # Install Rust
  - curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sudo -u ftr sh -s -- -y
  - echo 'source $HOME/.cargo/env' >> /home/ftr/.bashrc
  
  # Clone ftr repository
  - sudo -u ftr git clone https://github.com/dweekly/ftr /home/ftr/ftr
  
  # Configure SSH for easy access
  - sed -i 's/#Port 22/Port 22022/' /etc/ssh/sshd_config
  - systemctl restart sshd
  
  # Enable IP forwarding for testing
  - echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
  - sysctl -p

final_message: "ftr Ubuntu test VM ready!"
EOF

    # Meta data
    cat > "$SCRIPT_DIR/cloud-init/meta-data" <<'EOF'
instance-id: ftr-ubuntu-test
local-hostname: ftr-ubuntu
EOF
}

# Instructions for manual setup
show_manual_instructions() {
    echo -e "${BLUE}=== Manual VM Setup Instructions ===${NC}"
    echo
    echo "Since UTM doesn't have full CLI automation for VM creation, please:"
    echo
    echo -e "${YELLOW}1. Ubuntu Linux (22.04.5 LTS ARM64):${NC}"
    echo "   - Download: https://cdimage.ubuntu.com/releases/22.04/release/ubuntu-22.04.5-live-server-arm64.iso"
    echo "   - Or run: ./scripts/download-isos.sh to download automatically"
    echo "   - Create new VM in UTM: Virtualize → Linux → Browse for ISO"
    echo "   - Settings: 4GB RAM, 4 CPUs, 20GB disk"
    echo "   - IMPORTANT: Change Network to 'Bridged' mode (not NAT)"
    echo "   - Install with username 'ftr', hostname 'ftr-ubuntu'"
    echo "   - After install, run in VM:"
    echo "     curl -sSf https://sh.rustup.rs | sh"
    echo "     sudo apt update && sudo apt install -y build-essential git libpcap-dev"
    echo
    echo -e "${YELLOW}2. FreeBSD (14.3 ARM64):${NC}"
    echo "   - Download: https://download.freebsd.org/releases/arm64/aarch64/ISO-IMAGES/14.3/FreeBSD-14.3-RELEASE-arm64-aarch64-disc1.iso"
    echo "   - Or run: ./scripts/download-isos.sh to download automatically"
    echo "   - Create new VM in UTM: Virtualize → Other → Browse for ISO"
    echo "   - Settings: 4GB RAM, 4 CPUs, 20GB disk"
    echo "   - IMPORTANT: Change Network to 'Bridged' mode"
    echo "   - Install with username 'ftr', enable SSH"
    echo "   - After install, run in VM:"
    echo "     pkg install -y rust git"
    echo
    echo -e "${YELLOW}3. Windows 11:${NC}"
    echo "   - Download: https://www.microsoft.com/software-download/windows11"
    echo "   - Create new VM in UTM: Emulate → Windows"
    echo "   - Settings: 8GB RAM, 4 CPUs, 60GB disk"
    echo "   - IMPORTANT: Change Network to 'Bridged' mode"
    echo "   - After install:"
    echo "     - Install Npcap from https://npcap.com/#download"
    echo "     - Install Rust from https://rustup.rs"
    echo "     - Install Git for Windows"
    echo "     - Install Visual Studio Build Tools"
    echo
    echo -e "${BLUE}=== Network Bridge Setup ===${NC}"
    echo "Bridged networking allows VMs to get IPs on your local network."
    echo "This is essential for testing traceroute functionality."
    echo
    echo "In each VM's UTM settings:"
    echo "1. Stop the VM"
    echo "2. Edit → Network → Mode: Bridged"
    echo "3. Network → Bridged Interface: en0 (or your active interface)"
    echo "4. Start the VM"
    echo
}

# Generate SSH key for VM access
generate_ssh_key() {
    if [ ! -f "$HOME/.ssh/ftr-test-key" ]; then
        echo "Generating SSH key for VM access..."
        ssh-keygen -t ed25519 -f "$HOME/.ssh/ftr-test-key" -N "" -C "ftr-test-key"
        echo -e "${GREEN}SSH key generated at ~/.ssh/ftr-test-key${NC}"
        echo "Public key:"
        cat "$HOME/.ssh/ftr-test-key.pub"
        echo
        echo "Add this to your VMs during setup for passwordless access"
    fi
}

# Main execution
echo "Creating VM configuration files..."
create_ubuntu_config
create_freebsd_config  
create_windows_config
create_ubuntu_cloud_init

echo -e "${GREEN}Configuration files created in $SCRIPT_DIR/utm-configs/${NC}"
echo

generate_ssh_key
echo

show_manual_instructions

# Create helper script for SSH access
cat > "$SCRIPT_DIR/ssh-to-vm.sh" <<'EOF'
#!/bin/bash
# Helper to SSH into test VMs

VM=$1
case $VM in
    ubuntu)
        ssh -i ~/.ssh/ftr-test-key -p 22022 ftr@localhost
        ;;
    freebsd)
        ssh -i ~/.ssh/ftr-test-key -p 22023 ftr@localhost
        ;;
    *)
        echo "Usage: $0 [ubuntu|freebsd]"
        exit 1
        ;;
esac
EOF
chmod +x "$SCRIPT_DIR/ssh-to-vm.sh"

echo -e "${GREEN}Setup complete!${NC}"
echo "Next steps:"
echo "1. Create VMs in UTM following the instructions above"
echo "2. Use ./ssh-to-vm.sh [ubuntu|freebsd] to connect"
echo "3. Run ./test-cross-platform.sh to execute tests"