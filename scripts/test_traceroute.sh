#!/bin/bash
# Comprehensive test script for ftr
# Compares ftr output with system traceroute for various destinations and modes

set -e

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test configuration
DESTINATIONS=(
    "8.8.8.8"          # Google DNS
    "1.1.1.1"          # Cloudflare DNS
    "google.com"       # Google
    "github.com"       # GitHub
    "apple.com"        # Apple
)

# Platform detection
if [[ "$OSTYPE" == "darwin"* ]]; then
    PLATFORM="macOS"
    FTR_BIN="./target/debug/ftr"
    # macOS supports both ICMP and UDP without root
    MODES=("icmp" "udp")
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    PLATFORM="Linux"
    FTR_BIN="./target/debug/ftr"
    # Linux UDP works without root, ICMP needs root
    MODES=("udp")
    if [ "$EUID" -eq 0 ]; then
        MODES+=("icmp")
    fi
else
    echo -e "${RED}Unsupported platform: $OSTYPE${NC}"
    exit 1
fi

# Test results
declare -a TEST_RESULTS
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# Function to run a single test
run_test() {
    local dest=$1
    local mode=$2
    local queries=$3
    
    echo -e "\n${YELLOW}Testing: $dest (mode: $mode, queries: $queries)${NC}"
    
    # Run ftr
    echo "Running ftr..."
    if [ "$mode" == "icmp" ] && [ "$PLATFORM" == "Linux" ]; then
        # Need sudo for ICMP on Linux
        sudo $FTR_BIN --protocol $mode -q $queries --no-enrich $dest > /tmp/ftr_output.txt 2>&1
    else
        $FTR_BIN --protocol $mode -q $queries --no-enrich $dest > /tmp/ftr_output.txt 2>&1
    fi
    local ftr_exit=$?
    
    # Run system traceroute for comparison
    echo "Running system traceroute..."
    if [ "$PLATFORM" == "macOS" ]; then
        if [ "$mode" == "udp" ]; then
            traceroute -U -q $queries $dest > /tmp/sys_output.txt 2>&1
        else
            traceroute -I -q $queries $dest > /tmp/sys_output.txt 2>&1
        fi
    else
        # Linux
        if [ "$mode" == "udp" ]; then
            traceroute -U -q $queries $dest > /tmp/sys_output.txt 2>&1
        else
            sudo traceroute -I -q $queries $dest > /tmp/sys_output.txt 2>&1
        fi
    fi
    local sys_exit=$?
    
    # Extract hop count from outputs
    local ftr_hops=$(grep -E "^[[:space:]]*[0-9]+" /tmp/ftr_output.txt | tail -1 | awk '{print $1}')
    local sys_hops=$(grep -E "^[[:space:]]*[0-9]+" /tmp/sys_output.txt | tail -1 | awk '{print $1}')
    
    # Check if destination was reached
    local ftr_reached=$(grep -E "$dest|$(dig +short $dest 2>/dev/null | head -1)" /tmp/ftr_output.txt | grep -v "^ftr to" | wc -l)
    local sys_reached=$(grep -E "$dest|$(dig +short $dest 2>/dev/null | head -1)" /tmp/sys_output.txt | grep -v "^traceroute to" | wc -l)
    
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    
    # Determine test result
    local result="UNKNOWN"
    local details=""
    
    if [ $ftr_exit -eq 0 ] && [ $ftr_reached -gt 0 ]; then
        if [ -n "$ftr_hops" ] && [ -n "$sys_hops" ]; then
            local hop_diff=$((ftr_hops - sys_hops))
            if [ $hop_diff -ge -2 ] && [ $hop_diff -le 2 ]; then
                result="${GREEN}PASS${NC}"
                details="ftr: $ftr_hops hops, system: $sys_hops hops"
                PASSED_TESTS=$((PASSED_TESTS + 1))
            else
                result="${YELLOW}WARN${NC}"
                details="Hop count difference: ftr=$ftr_hops, system=$sys_hops"
                PASSED_TESTS=$((PASSED_TESTS + 1))
            fi
        else
            result="${GREEN}PASS${NC}"
            details="Destination reached"
            PASSED_TESTS=$((PASSED_TESTS + 1))
        fi
    else
        result="${RED}FAIL${NC}"
        details="ftr exit=$ftr_exit, destination reached=$ftr_reached"
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
    
    echo -e "Result: $result - $details"
    TEST_RESULTS+=("$dest|$mode|$queries|$result|$details")
    
    # Save outputs for debugging
    mkdir -p test_outputs
    cp /tmp/ftr_output.txt "test_outputs/${dest//\//_}_${mode}_q${queries}_ftr.txt"
    cp /tmp/sys_output.txt "test_outputs/${dest//\//_}_${mode}_q${queries}_sys.txt"
}

# Main test execution
echo -e "${GREEN}=== FTR Comprehensive Test Suite ===${NC}"
echo "Platform: $PLATFORM"
echo "FTR Binary: $FTR_BIN"
echo "Test Modes: ${MODES[*]}"
echo ""

# Build ftr
echo "Building ftr..."
cargo build

# Create test output directory
mkdir -p test_outputs

# Run tests
for dest in "${DESTINATIONS[@]}"; do
    for mode in "${MODES[@]}"; do
        # Test with 1 query
        run_test "$dest" "$mode" 1
        
        # Test with 3 queries (multiple probes)
        run_test "$dest" "$mode" 3
    done
done

# Print summary
echo -e "\n${GREEN}=== Test Summary ===${NC}"
echo "Total Tests: $TOTAL_TESTS"
echo -e "Passed: ${GREEN}$PASSED_TESTS${NC}"
echo -e "Failed: ${RED}$FAILED_TESTS${NC}"

# Print detailed results
echo -e "\n${GREEN}=== Detailed Results ===${NC}"
printf "%-20s %-6s %-8s %-10s %s\n" "Destination" "Mode" "Queries" "Result" "Details"
echo "--------------------------------------------------------------------------------"
for result in "${TEST_RESULTS[@]}"; do
    IFS='|' read -r dest mode queries res details <<< "$result"
    printf "%-20s %-6s %-8s %-10b %s\n" "$dest" "$mode" "$queries" "$res" "$details"
done

# Exit with appropriate code
if [ $FAILED_TESTS -gt 0 ]; then
    echo -e "\n${RED}Some tests failed. Check test_outputs/ for details.${NC}"
    exit 1
else
    echo -e "\n${GREEN}All tests passed!${NC}"
    exit 0
fi