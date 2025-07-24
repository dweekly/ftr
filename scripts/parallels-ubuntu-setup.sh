#!/bin/bash
# Quick setup script for Ubuntu in Parallels after OS installation

set -euo pipefail

echo "=== ftr Ubuntu Setup in Parallels ==="
echo

# Get VM IP
echo "Getting VM IP address..."
VM_IP=$(prlctl list -f | grep ftr-ubuntu | awk '{print $3}')

if [ "$VM_IP" = "-" ] || [ -z "$VM_IP" ]; then
    echo "VM doesn't have an IP yet. Please ensure:"
    echo "1. Ubuntu installation is complete"
    echo "2. VM has rebooted after installation"
    echo "3. Network is configured"
    echo
    echo "You can check IP inside VM with: ip addr show"
    exit 1
fi

echo "VM IP: $VM_IP"
echo

# Create setup script
cat > /tmp/ftr-ubuntu-setup.sh <<'EOF'
#!/bin/bash
set -euo pipefail

echo "=== Setting up ftr build environment ==="

# Update system
sudo apt update && sudo apt upgrade -y

# Install dependencies
sudo apt install -y build-essential git curl libpcap-dev net-tools iputils-ping traceroute

# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"

# Check for shared folder
if [ -d "/media/psf/ftr" ]; then
    echo "Found shared folder at /media/psf/ftr"
    cd /media/psf/ftr
    
    # Build ftr
    echo "Building ftr..."
    cargo build --release
    
    echo
    echo "=== Build complete! ==="
    echo "Testing ftr..."
    echo
    
    # Test non-root
    echo "Non-root test:"
    ./target/release/ftr google.com -m 5 || true
    
    echo
    # Test with root
    echo "Root test:"
    sudo ./target/release/ftr google.com -m 5 || true
    
else
    echo "Shared folder not found. Building from git..."
    git clone https://github.com/dweekly/ftr
    cd ftr
    cargo build --release
fi

echo
echo "=== Setup complete! ==="
echo "ftr is ready at: $(pwd)/target/release/ftr"
EOF

# Copy and run setup script
echo "Copying setup script to VM..."
scp -o StrictHostKeyChecking=no /tmp/ftr-ubuntu-setup.sh ftr@$VM_IP:~/

echo
echo "To complete setup, SSH into the VM and run the script:"
echo "  ssh ftr@$VM_IP"
echo "  chmod +x ftr-ubuntu-setup.sh"
echo "  ./ftr-ubuntu-setup.sh"
echo
echo "Or run directly:"
echo "  ssh ftr@$VM_IP 'bash -s' < /tmp/ftr-ubuntu-setup.sh"