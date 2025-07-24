#!/bin/bash
# Create Ubuntu VM from official ISO using Parallels

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ISO_PATH="$SCRIPT_DIR/iso-images/ubuntu-22.04.5-live-server-arm64.iso"
VM_NAME="ftr-ubuntu-iso"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}=== Creating Ubuntu VM from Official ISO ===${NC}"
echo

# Check for ISO
if [ ! -f "$ISO_PATH" ]; then
    echo -e "${YELLOW}Ubuntu ISO not found. Downloading...${NC}"
    "$SCRIPT_DIR/download-isos.sh"
fi

# Check if VM already exists
if prlctl list -a | grep -q "$VM_NAME"; then
    echo -e "${YELLOW}VM $VM_NAME already exists${NC}"
    read -p "Delete and recreate? (y/N) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        prlctl stop "$VM_NAME" --kill 2>/dev/null || true
        prlctl delete "$VM_NAME"
    else
        exit 0
    fi
fi

# Create Ubuntu autoinstall configuration
echo -e "${BLUE}Creating autoinstall configuration...${NC}"
mkdir -p "$SCRIPT_DIR/autoinstall"

# Create cloud-init autoinstall file
cat > "$SCRIPT_DIR/autoinstall/user-data" <<'EOF'
#cloud-config
autoinstall:
  version: 1
  locale: en_US.UTF-8
  keyboard:
    layout: us
  
  network:
    network:
      version: 2
      ethernets:
        enp0s5:
          dhcp4: yes
  
  storage:
    layout:
      name: direct
  
  identity:
    hostname: ftr-ubuntu
    username: ftr
    # Password is 'ftr' - mkpasswd -m sha-512
    password: $6$rounds=4096$7nKmATiC9iM3$QGNbkNUYO0H5.7MjzRXQJn5uYXYJu.z1C0fi9gTjJwKjL3nPRQgFKUwT7GxXtGHhxB3XAB1hRzQgRrCALqGqt/
  
  ssh:
    install-server: yes
    authorized-keys:
      - $(cat ~/.ssh/ftr-test-key.pub 2>/dev/null || echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...")
  
  packages:
    - build-essential
    - git
    - curl
    - libpcap-dev
    - net-tools
    - iputils-ping
    - traceroute
  
  late-commands:
    # Enable passwordless sudo
    - echo 'ftr ALL=(ALL) NOPASSWD:ALL' > /target/etc/sudoers.d/ftr
    # Install Rust
    - curtin in-target --target=/target -- sudo -u ftr bash -c 'curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y'
EOF

# Create VM
echo -e "${BLUE}Creating VM...${NC}"
prlctl create "$VM_NAME" --ostype linux

# Configure VM
echo -e "${BLUE}Configuring VM...${NC}"
# Set basic VM parameters
prlctl set "$VM_NAME" --memsize 4096 --cpus 4 --cpu-hotplug off

# Add CD-ROM with ISO
prlctl set "$VM_NAME" --device-set cdrom0 --image "$ISO_PATH"

# Set boot order
prlctl set "$VM_NAME" --device-bootorder "cdrom0 hdd0"

# Configure network
prlctl set "$VM_NAME" --device-set net0 --type bridged --iface en0

# Add shared folder
prlctl set "$VM_NAME" --shf-host-add ftr --path "$PROJECT_ROOT" --mode rw

echo -e "${GREEN}✓ VM created successfully${NC}"
echo
echo -e "${YELLOW}=== Manual Installation Steps ===${NC}"
echo "1. Start the VM:"
echo "   prlctl start $VM_NAME"
echo
echo "2. Open Parallels Desktop and access the VM console"
echo
echo "3. At the Ubuntu installer:"
echo "   - Wait for the installer to load"
echo "   - Select 'Ubuntu Server'"
echo "   - Follow installation prompts"
echo "   - Network should auto-configure"
echo "   - When prompted for user setup:"
echo "     - Your name: ftr"
echo "     - Server name: ftr-ubuntu"
echo "     - Username: ftr"
echo "     - Password: (your choice)"
echo "   - Enable OpenSSH server"
echo
echo "4. After installation completes and VM reboots:"
echo "   - Remove the ISO: prlctl set $VM_NAME --device-del cdrom0"
echo "   - Get IP: prlctl exec $VM_NAME ip addr show"
echo "   - SSH in: ssh ftr@<IP>"
echo
echo "5. Inside the VM, run:"
echo "   cd /media/psf/ftr"
echo "   cargo build --release"
echo "   ./target/release/ftr google.com"
echo
echo -e "${BLUE}Alternative: Automated Ubuntu Installation${NC}"
echo "For fully automated installation, consider using:"
echo "1. Packer with autoinstall.yaml"
echo "2. Ubuntu's subiquity autoinstall feature"
echo "3. A pre-built trusted base image"

# Start the VM
read -p "Start the VM now? (y/N) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    prlctl start "$VM_NAME"
    echo -e "${GREEN}VM started!${NC}"
    echo "Opening Parallels Desktop..."
    open -a "Parallels Desktop"
fi