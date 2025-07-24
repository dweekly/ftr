#!/bin/bash
# Quick test script for ftr vs system traceroute

set -e

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}=== Quick FTR Test ===${NC}"

# Test destinations
DESTINATIONS=("8.8.8.8" "1.1.1.1")

for dest in "${DESTINATIONS[@]}"; do
    echo -e "\n${YELLOW}Testing $dest with ICMP:${NC}"
    
    # Run ftr
    echo "FTR output:"
    ./target/release/ftr --protocol icmp $dest 2>&1 | tail -5
    
    echo -e "\nSystem traceroute output:"
    traceroute -I -q 1 $dest 2>&1 | tail -5
    
    echo -e "\n${YELLOW}Testing $dest with UDP:${NC}"
    
    # Run ftr
    echo "FTR output:"
    ./target/release/ftr --protocol udp $dest 2>&1 | tail -5
    
    echo -e "\nSystem traceroute output:"
    traceroute -U -q 1 $dest 2>&1 | tail -5
done

echo -e "\n${GREEN}Quick test completed!${NC}"