#!/bin/bash
# Test ftr on Windows - to be run in Git Bash or WSL

set -euo pipefail

# This script is meant to be run on Windows in Git Bash
# For native Windows testing, use test-windows.ps1

echo "=== ftr Windows Test Suite (Git Bash) ==="
echo "System: $(uname -s)"
echo

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Check if we're in Git Bash or WSL
if [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "cygwin" ]]; then
    echo "Running in Git Bash/Cygwin environment"
    IS_WINDOWS_NATIVE=true
elif grep -qi microsoft /proc/version 2>/dev/null; then
    echo "Running in WSL"
    IS_WINDOWS_NATIVE=false
else
    echo -e "${RED}This script should be run on Windows (Git Bash or WSL)${NC}"
    exit 1
fi

# For native Windows execution, we need PowerShell
if [ "$IS_WINDOWS_NATIVE" = true ]; then
    echo -e "${YELLOW}Switching to PowerShell for Windows testing...${NC}"
    powershell.exe -ExecutionPolicy Bypass -File "$(dirname "$0")/test-windows.ps1"
    exit $?
fi

# WSL testing continues here
echo -e "${BLUE}=== Testing in WSL ===${NC}"
echo "Note: This tests the Linux subsystem, not native Windows"
echo

cd ~/ftr || { echo "ftr directory not found"; exit 1; }

# Run Linux tests in WSL
./scripts/test-ubuntu.sh