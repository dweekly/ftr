#!/bin/bash
# Test script for FreeBSD root functionality

set -euo pipefail

FREEBSD_VM="ftr@192.168.53.178"
SSH_KEY="$HOME/.ssh/ftr_vm_key"
FTR_DIR="$HOME/ftr"  # FreeBSD has no shared mount, files are copied

echo "=== FreeBSD Root Functionality Test ==="
echo

# Function to run command on FreeBSD VM
run_on_freebsd() {
    local cmd="$1"
    echo "Running: $cmd"
    ssh -i "$SSH_KEY" "$FREEBSD_VM" "$cmd"
    echo
}

# Test 1: Verify sudo works
echo "1. Testing sudo access..."
run_on_freebsd "sudo whoami"

# Test 2: Test ftr with root (localhost)
echo "2. Testing ftr with root (localhost)..."
run_on_freebsd "cd $FTR_DIR && sudo ./target/release/ftr --max-hops 3 127.0.0.1"

# Test 3: Test ftr with root (external)
echo "3. Testing ftr with root (external host)..."
run_on_freebsd "cd $FTR_DIR && sudo ./target/release/ftr --max-hops 10 8.8.8.8"

# Test 4: Test verbose mode
echo "4. Testing verbose mode..."
run_on_freebsd "cd $FTR_DIR && sudo ./target/release/ftr -v --max-hops 3 google.com"

# Test 5: Test JSON output
echo "5. Testing JSON output..."
run_on_freebsd "cd $FTR_DIR && sudo ./target/release/ftr --json --max-hops 5 1.1.1.1"

# Test 6: Verify ICMP mode is being used
echo "6. Verifying Raw ICMP mode..."
run_on_freebsd "cd $FTR_DIR && sudo ./target/release/ftr -v --max-hops 1 8.8.8.8 2>&1 | grep 'Using Raw ICMP'"

# Test 7: Test non-root fails appropriately
echo "7. Testing non-root error..."
run_on_freebsd "cd $FTR_DIR && ./target/release/ftr --max-hops 1 8.8.8.8 2>&1 | grep 'requires root privileges'"

echo "=== All tests completed ==="