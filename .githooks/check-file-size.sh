#!/bin/bash
# Check for large files being committed

# Color codes
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

# Size limits (in bytes)
WARN_SIZE=$((10 * 1024 * 1024))  # 10MB
FAIL_SIZE=$((50 * 1024 * 1024))  # 50MB

# Get list of files to be committed
FILES=$(git diff --cached --name-only --diff-filter=ACM)

# Track if we have issues
HAS_WARNING=0
HAS_ERROR=0

# Patterns for files that should trigger warnings
BINARY_PATTERNS="*.iso *.img *.dmg *.vdi *.vmdk *.vhd *.vhdx *.ova *.ovf *.qcow2 *.zip *.tar.gz *.tar.bz2 *.7z *.rar"

echo "Checking file sizes..."

for file in $FILES; do
    if [ -f "$file" ]; then
        # Check for binary/archive file patterns
        for pattern in $BINARY_PATTERNS; do
            case "$file" in
                $pattern)
                    printf "${YELLOW}⚠ WARNING: Binary/archive file detected: %s${NC}\n" "$file"
                    echo "  Consider if this file should be in version control"
                    HAS_WARNING=1
                    ;;
            esac
        done
        
        SIZE=$(stat -f%z "$file" 2>/dev/null || stat -c%s "$file" 2>/dev/null)
        
        if [ -n "$SIZE" ]; then
            if [ "$SIZE" -gt "$FAIL_SIZE" ]; then
                SIZE_MB=$((SIZE / 1024 / 1024))
                printf "${RED}✗ ERROR: File too large (${SIZE_MB}MB): %s${NC}\n" "$file"
                echo "  Files larger than 50MB must use Git LFS or be excluded from the repository"
                HAS_ERROR=1
            elif [ "$SIZE" -gt "$WARN_SIZE" ]; then
                SIZE_MB=$((SIZE / 1024 / 1024))
                printf "${YELLOW}⚠ WARNING: Large file (${SIZE_MB}MB): %s${NC}\n" "$file"
                echo "  Consider using Git LFS for files larger than 10MB"
                HAS_WARNING=1
            fi
        fi
    fi
done

if [ "$HAS_ERROR" -eq 1 ]; then
    echo ""
    echo "${RED}Commit blocked due to files exceeding 50MB limit.${NC}"
    echo "Options:"
    echo "1. Use Git LFS: git lfs track '*.extension'"
    echo "2. Add to .gitignore if the file shouldn't be tracked"
    echo "3. Remove the file from staging: git reset HEAD <file>"
    exit 1
elif [ "$HAS_WARNING" -eq 1 ]; then
    echo ""
    echo "${YELLOW}Large files detected but within acceptable limits.${NC}"
    echo "Consider using Git LFS for better performance."
else
    printf "${GREEN}✓ All file sizes OK${NC}\n"
fi

exit 0