#!/bin/bash
# Test ftr on Ubuntu with different privilege levels and socket modes

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}=== ftr Ubuntu Test Suite ===${NC}"
echo "Testing on: $(lsb_release -d | cut -f2)"
echo "Kernel: $(uname -r)"
echo

# Function to test ftr with specific conditions
test_ftr() {
    local test_name=$1
    local command=$2
    local expected_result=$3
    
    echo -e "${YELLOW}Test: $test_name${NC}"
    echo "Command: $command"
    
    if eval "$command" > /tmp/ftr-test.log 2>&1; then
        if [ "$expected_result" = "success" ]; then
            echo -e "${GREEN}✓ PASSED${NC}"
            echo "Output:"
            head -10 /tmp/ftr-test.log
            echo
        else
            echo -e "${RED}✗ FAILED: Expected failure but succeeded${NC}"
            return 1
        fi
    else
        if [ "$expected_result" = "failure" ]; then
            echo -e "${GREEN}✓ PASSED (expected failure)${NC}"
            echo "Error output:"
            tail -5 /tmp/ftr-test.log
            echo
        else
            echo -e "${RED}✗ FAILED${NC}"
            cat /tmp/ftr-test.log
            return 1
        fi
    fi
}

# Navigate to ftr directory
cd ~/ftr || { echo "ftr directory not found"; exit 1; }

# Ensure we have the latest code
echo "Updating ftr repository..."
git pull

# Build ftr
echo "Building ftr..."
source ~/.cargo/env
cargo build --release

# Path to ftr binary
FTR_BIN="./target/release/ftr"

echo -e "${BLUE}=== Testing Without Root Privileges ===${NC}"
echo

# Test 1: Non-root DGRAM ICMP (should work on Linux)
test_ftr "DGRAM ICMP without root" \
    "$FTR_BIN google.com -m 5" \
    "success"

# Test 2: Force RAW mode without root (should fail)
test_ftr "RAW ICMP without root (should fail)" \
    "RUST_LOG=debug $FTR_BIN google.com -m 5 2>&1 | grep -i 'permission denied'" \
    "success"

echo -e "${BLUE}=== Testing With Root Privileges ===${NC}"
echo

# Test 3: Root with default mode (should use best available)
test_ftr "Default mode with root" \
    "sudo $FTR_BIN google.com -m 10" \
    "success"

# Test 4: Explicit socket mode testing
echo -e "${BLUE}=== Testing Socket Fallback Behavior ===${NC}"

# Test different targets
TARGETS=("google.com" "1.1.1.1" "github.com")

for target in "${TARGETS[@]}"; do
    echo -e "${YELLOW}Testing target: $target${NC}"
    
    # Non-root test
    echo "Non-root test:"
    timeout 10s $FTR_BIN "$target" -m 5 --overall-timeout-ms 5000 || true
    
    # Root test
    echo "Root test:"
    timeout 10s sudo $FTR_BIN "$target" -m 5 --overall-timeout-ms 5000 || true
    
    echo "---"
done

# Test 5: Performance comparison
echo -e "${BLUE}=== Performance Testing ===${NC}"

echo "Traditional traceroute (for comparison):"
time timeout 10s traceroute -m 10 google.com || true

echo
echo "ftr (non-root):"
time $FTR_BIN google.com -m 10 --overall-timeout-ms 5000

echo
echo "ftr (root):"
time sudo $FTR_BIN google.com -m 10 --overall-timeout-ms 5000

# Test 6: IPv6 support check
echo -e "${BLUE}=== IPv6 Support Test ===${NC}"
if ping6 -c 1 google.com > /dev/null 2>&1; then
    test_ftr "IPv6 target" \
        "$FTR_BIN ipv6.google.com -m 5" \
        "success"
else
    echo "IPv6 not available on this system"
fi

# Test 7: Error handling
echo -e "${BLUE}=== Error Handling Tests ===${NC}"

test_ftr "Invalid hostname" \
    "$FTR_BIN invalid.hostname.that.does.not.exist" \
    "failure"

test_ftr "Unreachable private IP" \
    "$FTR_BIN 192.168.255.255 --overall-timeout-ms 1000" \
    "success"

# Summary
echo -e "${BLUE}=== Test Summary ===${NC}"
echo "Socket modes available:"
echo -n "  DGRAM ICMP (non-root): "
if $FTR_BIN google.com -m 1 > /dev/null 2>&1; then
    echo -e "${GREEN}Available${NC}"
else
    echo -e "${RED}Not available${NC}"
fi

echo -n "  RAW ICMP (root): "
if sudo $FTR_BIN google.com -m 1 > /dev/null 2>&1; then
    echo -e "${GREEN}Available${NC}"
else
    echo -e "${RED}Not available${NC}"
fi

# Check for any issues
echo
echo -e "${BLUE}=== System Information ===${NC}"
echo "Capabilities:"
getcap $FTR_BIN 2>/dev/null || echo "No special capabilities set"

echo
echo "Socket permissions:"
ls -la /proc/sys/net/ipv4/ping_group_range 2>/dev/null || true
cat /proc/sys/net/ipv4/ping_group_range 2>/dev/null || true

echo
echo -e "${GREEN}Ubuntu testing complete!${NC}"