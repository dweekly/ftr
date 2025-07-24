#!/bin/bash
# Cross-platform testing orchestrator for ftr using UTM

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "=== ftr Cross-Platform Testing Suite ==="
echo

# Check if UTM is installed
UTMCTL="/Applications/UTM.app/Contents/MacOS/utmctl"
if [ ! -x "$UTMCTL" ]; then
    echo -e "${RED}Error: UTM CLI (utmctl) not found${NC}"
    echo "Please install UTM from https://mac.getutm.app/"
    exit 1
fi

# Function to check if VM exists
vm_exists() {
    "$UTMCTL" list | grep -q "^$1$" || return 1
}

# Function to start VM if not running
ensure_vm_running() {
    local vm_name=$1
    if ! "$UTMCTL" status "$vm_name" 2>/dev/null | grep -q "started"; then
        echo "Starting VM: $vm_name"
        "$UTMCTL" start "$vm_name"
        echo "Waiting for VM to boot..."
        sleep 30
    fi
}

# Function to run tests in VM
run_tests_in_vm() {
    local vm_name=$1
    local test_script=$2
    
    echo -e "${YELLOW}Testing in $vm_name...${NC}"
    
    if ! vm_exists "$vm_name"; then
        echo -e "${RED}VM '$vm_name' not found. Please run setup script first.${NC}"
        return 1
    fi
    
    ensure_vm_running "$vm_name"
    
    # Copy test script to VM and run it
    # Note: This assumes SSH is set up. For Windows, we'd use RDP or WinRM
    case $vm_name in
        ftr-ubuntu|ftr-freebsd)
            # Assumes SSH key is set up during VM creation
            scp -o StrictHostKeyChecking=no -P 22022 "$test_script" ftr@localhost:/tmp/test.sh
            ssh -o StrictHostKeyChecking=no -p 22022 ftr@localhost "chmod +x /tmp/test.sh && /tmp/test.sh"
            ;;
        ftr-windows)
            echo "Windows testing requires manual intervention or WinRM setup"
            ;;
    esac
}

# Main menu
echo "Select testing option:"
echo "1) Test on Ubuntu Linux"
echo "2) Test on FreeBSD" 
echo "3) Test on Windows"
echo "4) Test on all platforms"
echo "5) Setup VMs (if not already done)"
echo

read -p "Enter choice (1-5): " choice

case $choice in
    1)
        run_tests_in_vm "ftr-ubuntu" "$SCRIPT_DIR/test-ubuntu.sh"
        ;;
    2)
        run_tests_in_vm "ftr-freebsd" "$SCRIPT_DIR/test-freebsd.sh"
        ;;
    3)
        run_tests_in_vm "ftr-windows" "$SCRIPT_DIR/test-windows.sh"
        ;;
    4)
        run_tests_in_vm "ftr-ubuntu" "$SCRIPT_DIR/test-ubuntu.sh"
        run_tests_in_vm "ftr-freebsd" "$SCRIPT_DIR/test-freebsd.sh"
        run_tests_in_vm "ftr-windows" "$SCRIPT_DIR/test-windows.sh"
        ;;
    5)
        echo "Running VM setup scripts..."
        "$SCRIPT_DIR/setup-utm-vms.sh"
        ;;
    *)
        echo -e "${RED}Invalid choice${NC}"
        exit 1
        ;;
esac

echo -e "${GREEN}Testing complete!${NC}"