#!/bin/bash
# Download ISO images for UTM VMs

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ISO_DIR="$SCRIPT_DIR/iso-images"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}=== Downloading ISO Images for ftr Testing ===${NC}"
echo

# Create ISO directory
mkdir -p "$ISO_DIR"

# Function to download with progress
download_iso() {
    local name=$1
    local url=$2
    local filename=$(basename "$url")
    local filepath="$ISO_DIR/$filename"
    
    echo -e "${YELLOW}Downloading $name...${NC}"
    
    if [ -f "$filepath" ]; then
        echo -e "${GREEN}✓ Already downloaded: $filename${NC}"
        return 0
    fi
    
    echo "URL: $url"
    echo "Saving to: $filepath"
    
    if curl -L -# -o "$filepath" "$url"; then
        echo -e "${GREEN}✓ Downloaded successfully${NC}"
    else
        echo -e "${RED}✗ Download failed${NC}"
        rm -f "$filepath"
        return 1
    fi
    echo
}

# Ubuntu 22.04 LTS ARM64
download_iso "Ubuntu 22.04.5 LTS ARM64 Server" \
    "https://cdimage.ubuntu.com/releases/22.04/release/ubuntu-22.04.5-live-server-arm64.iso"

# FreeBSD 14.3 ARM64
download_iso "FreeBSD 14.3 ARM64" \
    "https://download.freebsd.org/releases/arm64/aarch64/ISO-IMAGES/14.3/FreeBSD-14.3-RELEASE-arm64-aarch64-disc1.iso"

# Windows 11 ARM64 (if available)
echo -e "${YELLOW}Windows 11 ARM64:${NC}"
echo "Windows 11 ARM64 ISO must be downloaded manually from:"
echo "https://www.microsoft.com/software-download/windows11"
echo "Use the Windows 11 Installation Assistant or Media Creation Tool"
echo "For ARM64 testing on Apple Silicon, you may need Windows 11 ARM64 Insider Preview"
echo

# Show summary
echo -e "${BLUE}=== Download Summary ===${NC}"
echo "ISO images are saved in: $ISO_DIR"
echo
ls -lh "$ISO_DIR" 2>/dev/null || echo "No ISOs downloaded yet"
echo

echo -e "${GREEN}Downloads complete!${NC}"
echo "Next step: Run ./setup-utm-vms.sh to see VM setup instructions"