#!/bin/bash
# Setup Parallels Desktop VMs for cross-platform ftr testing

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}=== Parallels Desktop VM Setup for ftr Testing ===${NC}"
echo

# Check for Parallels Desktop
if ! command -v prlctl &> /dev/null; then
    echo -e "${RED}Error: Parallels Desktop CLI not found${NC}"
    echo "Please ensure Parallels Desktop is installed and prlctl is in your PATH"
    echo "You may need to add: /Applications/Parallels Desktop.app/Contents/MacOS to your PATH"
    exit 1
fi

echo -e "${GREEN}✓ Parallels Desktop detected${NC}"
prlctl --version

# Function to check if VM exists
vm_exists() {
    prlctl list -a | grep -q "$1" || return 1
}

# Function to create Ubuntu VM
create_ubuntu_vm() {
    local vm_name="ftr-ubuntu"
    
    if vm_exists "$vm_name"; then
        echo -e "${YELLOW}VM $vm_name already exists${NC}"
        return 0
    fi
    
    echo -e "${BLUE}Creating Ubuntu 22.04 ARM64 VM...${NC}"
    
    # Download Ubuntu if needed
    if [ ! -f "$SCRIPT_DIR/iso-images/ubuntu-22.04.5-live-server-arm64.iso" ]; then
        echo "Downloading Ubuntu ISO..."
        ./scripts/download-isos.sh
    fi
    
    # Create VM
    prlctl create "$vm_name" --distribution ubuntu --location "$SCRIPT_DIR/iso-images/ubuntu-22.04.5-live-server-arm64.iso"
    
    # Configure VM
    prlctl set "$vm_name" --memsize 4096
    prlctl set "$vm_name" --cpus 4
    prlctl set "$vm_name" --device-set hdd0 --size 20480
    prlctl set "$vm_name" --device-set net0 --type bridged --iface en0
    prlctl set "$vm_name" --shared-folder-add ftr --path "$PROJECT_ROOT"
    
    echo -e "${GREEN}✓ Ubuntu VM created${NC}"
}

# Function to create FreeBSD VM
create_freebsd_vm() {
    local vm_name="ftr-freebsd"
    
    if vm_exists "$vm_name"; then
        echo -e "${YELLOW}VM $vm_name already exists${NC}"
        return 0
    fi
    
    echo -e "${BLUE}Creating FreeBSD 14.3 ARM64 VM...${NC}"
    
    # Download FreeBSD if needed
    if [ ! -f "$SCRIPT_DIR/iso-images/FreeBSD-14.3-RELEASE-arm64-aarch64-disc1.iso" ]; then
        echo "Downloading FreeBSD ISO..."
        ./scripts/download-isos.sh
    fi
    
    # Create VM (Parallels may not have FreeBSD template, use generic)
    prlctl create "$vm_name" --ostype other --location "$SCRIPT_DIR/iso-images/FreeBSD-14.3-RELEASE-arm64-aarch64-disc1.iso"
    
    # Configure VM
    prlctl set "$vm_name" --memsize 4096
    prlctl set "$vm_name" --cpus 4
    prlctl set "$vm_name" --device-set hdd0 --size 20480
    prlctl set "$vm_name" --device-set net0 --type bridged --iface en0
    prlctl set "$vm_name" --shared-folder-add ftr --path "$PROJECT_ROOT"
    
    echo -e "${GREEN}✓ FreeBSD VM created${NC}"
}

# Function to create Windows VM
create_windows_vm() {
    local vm_name="ftr-windows"
    
    if vm_exists "$vm_name"; then
        echo -e "${YELLOW}VM $vm_name already exists${NC}"
        return 0
    fi
    
    echo -e "${BLUE}Creating Windows 11 VM...${NC}"
    echo "Note: Parallels can download Windows 11 automatically"
    
    # Let Parallels handle Windows download and setup
    prlctl create "$vm_name" --distribution win-11
    
    # Configure VM
    prlctl set "$vm_name" --memsize 8192
    prlctl set "$vm_name" --cpus 4
    prlctl set "$vm_name" --device-set net0 --type bridged --iface en0
    prlctl set "$vm_name" --shared-folder-add ftr --path "$PROJECT_ROOT"
    
    echo -e "${GREEN}✓ Windows VM created${NC}"
}

# Create post-install script for automation
create_automation_scripts() {
    mkdir -p "$SCRIPT_DIR/parallels"
    
    # Ubuntu automation script
    cat > "$SCRIPT_DIR/parallels/ubuntu-setup.sh" <<'EOF'
#!/bin/bash
# Automated setup for Ubuntu VM

set -euo pipefail

echo "=== Automated Ubuntu Setup for ftr ==="

# Update system
sudo apt update && sudo apt upgrade -y

# Install dependencies
sudo apt install -y build-essential git curl libpcap-dev net-tools iputils-ping traceroute

# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"

# Mount shared folder if not already mounted
if [ ! -d "/media/psf/ftr" ] && [ ! -d "/mnt/ftr" ]; then
    sudo mkdir -p /mnt/ftr
    # Parallels usually auto-mounts at /media/psf/
fi

# Build ftr from shared folder
if [ -d "/media/psf/ftr" ]; then
    cd /media/psf/ftr
elif [ -d "/mnt/ftr" ]; then
    cd /mnt/ftr
else
    # Fallback to git clone
    git clone https://github.com/dweekly/ftr
    cd ftr
fi

cargo build --release

echo "=== Setup complete! ==="
echo "ftr binary: $(pwd)/target/release/ftr"
EOF

    chmod +x "$SCRIPT_DIR/parallels/ubuntu-setup.sh"
    
    # Windows automation script (PowerShell)
    cat > "$SCRIPT_DIR/parallels/windows-setup.ps1" <<'EOF'
# Automated setup for Windows VM

Write-Host "=== Automated Windows Setup for ftr ===" -ForegroundColor Blue

# Check for admin rights
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Please run as Administrator" -ForegroundColor Red
    exit 1
}

# Install Chocolatey if not present
if (!(Get-Command choco -ErrorAction SilentlyContinue)) {
    Write-Host "Installing Chocolatey..." -ForegroundColor Yellow
    Set-ExecutionPolicy Bypass -Scope Process -Force
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
    iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
}

# Install dependencies
Write-Host "Installing dependencies..." -ForegroundColor Yellow
choco install -y git rustup.install visualstudio2022buildtools npcap

# Refresh environment
$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")

# Build ftr
Write-Host "Building ftr..." -ForegroundColor Yellow
$ftrPath = "Z:\ftr"  # Parallels shared folder typically maps to Z:
if (Test-Path $ftrPath) {
    Set-Location $ftrPath
} else {
    git clone https://github.com/dweekly/ftr
    Set-Location ftr
}

cargo build --release

Write-Host "=== Setup complete! ===" -ForegroundColor Green
Write-Host "ftr binary: $(Get-Location)\target\release\ftr.exe"
EOF
    
    echo -e "${GREEN}✓ Created automation scripts in $SCRIPT_DIR/parallels/${NC}"
}

# Main menu
echo "Select VMs to create:"
echo "1) Ubuntu Linux"
echo "2) FreeBSD"
echo "3) Windows 11"
echo "4) All VMs"
echo "5) Just create automation scripts"
echo

read -p "Enter choice (1-5): " choice

case $choice in
    1)
        create_ubuntu_vm
        create_automation_scripts
        ;;
    2)
        create_freebsd_vm
        create_automation_scripts
        ;;
    3)
        create_windows_vm
        create_automation_scripts
        ;;
    4)
        create_ubuntu_vm
        create_freebsd_vm
        create_windows_vm
        create_automation_scripts
        ;;
    5)
        create_automation_scripts
        ;;
    *)
        echo -e "${RED}Invalid choice${NC}"
        exit 1
        ;;
esac

echo
echo -e "${GREEN}Setup complete!${NC}"
echo
echo "Next steps:"
echo "1. Start VMs: prlctl start <vm-name>"
echo "2. For Ubuntu/FreeBSD: Copy and run the setup script from $SCRIPT_DIR/parallels/"
echo "3. For Windows: Run the PowerShell script as Administrator"
echo
echo "Useful Parallels commands:"
echo "  prlctl list -a              # List all VMs"
echo "  prlctl start ftr-ubuntu     # Start Ubuntu VM"
echo "  prlctl enter ftr-ubuntu     # Open VM console"
echo "  prlctl exec ftr-ubuntu ls   # Run command in VM"
echo
echo "Shared folder is mounted at:"
echo "  Ubuntu/FreeBSD: /media/psf/ftr or /mnt/ftr"
echo "  Windows: Z:\\ftr"