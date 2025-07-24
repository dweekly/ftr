#!/bin/sh
# Test ftr on FreeBSD with different privilege levels and socket modes

set -eu

# Colors (POSIX compatible)
RED='[0;31m'
GREEN='[0;32m'
YELLOW='[1;33m'
BLUE='[0;34m'
NC='[0m'

echo "${BLUE}=== ftr FreeBSD Test Suite ===${NC}"
echo "Testing on: $(uname -srm)"
echo "Version: $(freebsd-version)"
echo

# Function to test ftr
test_ftr() {
    test_name=$1
    command=$2
    expected_result=$3
    
    echo "${YELLOW}Test: $test_name${NC}"
    echo "Command: $command"
    
    if eval "$command" > /tmp/ftr-test.log 2>&1; then
        if [ "$expected_result" = "success" ]; then
            echo "${GREEN}✓ PASSED${NC}"
            echo "Output:"
            head -10 /tmp/ftr-test.log
            echo
        else
            echo "${RED}✗ FAILED: Expected failure but succeeded${NC}"
            return 1
        fi
    else
        exit_code=$?
        if [ "$expected_result" = "failure" ]; then
            echo "${GREEN}✓ PASSED (expected failure)${NC}"
            echo "Error output:"
            tail -5 /tmp/ftr-test.log
            echo
        else
            echo "${RED}✗ FAILED (exit code: $exit_code)${NC}"
            cat /tmp/ftr-test.log
            return 1
        fi
    fi
}

# Navigate to ftr directory
cd ~/ftr || { echo "ftr directory not found"; exit 1; }

# Update repository
echo "Updating ftr repository..."
git pull

# Build ftr
echo "Building ftr..."
cargo build --release

# Path to ftr binary
FTR_BIN="./target/release/ftr"

echo "${BLUE}=== Testing Without Root Privileges ===${NC}"
echo

# Test 1: Non-root on FreeBSD (will likely need root)
test_ftr "ICMP without root (may fail on FreeBSD)" \
    "$FTR_BIN google.com -m 5" \
    "failure"

echo "${BLUE}=== Testing With Root Privileges ===${NC}"
echo

# Test 2: Root with default mode
test_ftr "Default mode with root" \
    "doas $FTR_BIN google.com -m 10" \
    "success"

# Test 3: Test with different targets
echo "${BLUE}=== Testing Different Targets ===${NC}"

for target in google.com 1.1.1.1 cloudflare.com; do
    echo "${YELLOW}Testing target: $target${NC}"
    
    # Root test (FreeBSD typically requires root for raw sockets)
    echo "Root test:"
    timeout 10s doas $FTR_BIN "$target" -m 5 --overall-timeout-ms 5000 || true
    
    echo "---"
done

# Test 4: Performance comparison
echo "${BLUE}=== Performance Testing ===${NC}"

echo "System traceroute (for comparison):"
time timeout 10s traceroute -m 10 google.com || true

echo
echo "ftr with root:"
time doas $FTR_BIN google.com -m 10 --overall-timeout-ms 5000

# Test 5: IPv6 support check
echo "${BLUE}=== IPv6 Support Test ===${NC}"
if ping6 -c 1 google.com > /dev/null 2>&1; then
    test_ftr "IPv6 target" \
        "doas $FTR_BIN 2001:4860:4860::8888 -m 5" \
        "success"
else
    echo "IPv6 not available on this system"
fi

# Test 6: Error handling
echo "${BLUE}=== Error Handling Tests ===${NC}"

test_ftr "Invalid hostname" \
    "doas $FTR_BIN invalid.hostname.that.does.not.exist" \
    "failure"

test_ftr "Unreachable private IP" \
    "doas $FTR_BIN 192.168.255.255 --overall-timeout-ms 1000" \
    "success"

# Test 7: FreeBSD-specific tests
echo "${BLUE}=== FreeBSD-Specific Tests ===${NC}"

# Check if we can use BPF (Berkeley Packet Filter)
echo "BPF device availability:"
ls -la /dev/bpf* | head -5 || echo "No BPF devices found"

# Test with jails if available
if command -v jls > /dev/null 2>&1; then
    echo
    echo "Jail information:"
    jls || echo "No jails running"
fi

# Summary
echo "${BLUE}=== Test Summary ===${NC}"
echo "Socket modes available on FreeBSD:"
echo -n "  RAW ICMP (root): "
if doas $FTR_BIN google.com -m 1 > /dev/null 2>&1; then
    echo "${GREEN}Available${NC}"
else
    echo "${RED}Not available${NC}"
fi

# System information
echo
echo "${BLUE}=== System Information ===${NC}"
echo "Network interfaces:"
ifconfig | grep -E '^[a-z]|inet ' | head -10

echo
echo "Firewall status:"
doas pfctl -s info 2>/dev/null | head -5 || echo "PF not running"

echo
echo "Security levels:"
sysctl security.bsd.see_other_uids || true
sysctl security.bsd.unprivileged_read_msgbuf || true

echo
echo "${GREEN}FreeBSD testing complete!${NC}"

# Notes for FreeBSD
echo
echo "${YELLOW}Notes for FreeBSD:${NC}"
echo "- FreeBSD typically requires root for raw socket operations"
echo "- DGRAM ICMP sockets may not be available like on Linux"
echo "- Consider using setuid or sudo/doas for production use"
echo "- PF firewall rules may affect ICMP operations"