#!/bin/bash
# Release checklist script - Run before cutting a new release

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== RELEASE CHECKLIST ===${NC}"
echo ""

# Function to confirm action
confirm() {
    read -p "$1 [y/N] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        return 1
    fi
    return 0
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# 1. Check git status
echo "1. Checking git status..."
if [ -n "$(git status --porcelain)" ]; then
    echo -e "${RED}✗ Working directory not clean${NC}"
    git status --short
    exit 1
else
    echo -e "${GREEN}✓ Working directory clean${NC}"
fi

# 2. Check current branch
CURRENT_BRANCH=$(git branch --show-current)
echo ""
echo "2. Current branch: $CURRENT_BRANCH"
if [ "$CURRENT_BRANCH" != "main" ]; then
    echo -e "${YELLOW}Warning: Not on main branch${NC}"
    if ! confirm "Continue anyway?"; then
        exit 1
    fi
fi

# 3. Run all compliance checks
echo ""
echo "3. Running compliance checks..."
echo ""

FAILED=0

# Format check
echo -n "  Format check... "
if cargo fmt -- --check >/dev/null 2>&1; then
    echo -e "${GREEN}✓${NC}"
else
    echo -e "${RED}✗${NC}"
    FAILED=1
fi

# Clippy check
echo -n "  Clippy check... "
if cargo clippy -- -D warnings >/dev/null 2>&1; then
    echo -e "${GREEN}✓${NC}"
else
    echo -e "${RED}✗${NC}"
    FAILED=1
fi

# Test check
echo -n "  Test check... "
if cargo test --quiet >/dev/null 2>&1; then
    echo -e "${GREEN}✓${NC}"
else
    echo -e "${RED}✗${NC}"
    FAILED=1
fi

# Doc check
echo -n "  Documentation check... "
if cargo doc --no-deps --quiet >/dev/null 2>&1; then
    echo -e "${GREEN}✓${NC}"
else
    echo -e "${RED}✗${NC}"
    FAILED=1
fi

# Security audit
echo -n "  Security audit... "
if command_exists cargo-audit; then
    if cargo audit --quiet >/dev/null 2>&1; then
        echo -e "${GREEN}✓${NC}"
    else
        echo -e "${RED}✗ (vulnerabilities found)${NC}"
        FAILED=1
    fi
else
    echo -e "${YELLOW}skipped (cargo-audit not installed)${NC}"
fi

# Unused dependencies
echo -n "  Unused dependencies... "
if command_exists cargo-machete; then
    if cargo machete >/dev/null 2>&1; then
        echo -e "${GREEN}✓${NC}"
    else
        echo -e "${RED}✗${NC}"
        FAILED=1
    fi
else
    echo -e "${YELLOW}skipped (cargo-machete not installed)${NC}"
fi

if [ $FAILED -ne 0 ]; then
    echo ""
    echo -e "${RED}Some checks failed. Please fix before releasing.${NC}"
    exit 1
fi

# 4. Build release
echo ""
echo "4. Building release..."
if cargo build --release; then
    echo -e "${GREEN}✓ Release build successful${NC}"
    BINARY_SIZE=$(stat -f%z target/release/ftr 2>/dev/null || stat -c%s target/release/ftr 2>/dev/null)
    if [ -n "$BINARY_SIZE" ]; then
        # Convert to human readable
        if [ "$BINARY_SIZE" -ge 1048576 ]; then
            BINARY_SIZE="$((BINARY_SIZE / 1048576))MB"
        elif [ "$BINARY_SIZE" -ge 1024 ]; then
            BINARY_SIZE="$((BINARY_SIZE / 1024))KB"
        else
            BINARY_SIZE="${BINARY_SIZE}B"
        fi
    fi
    echo "  Binary size: $BINARY_SIZE"
else
    echo -e "${RED}✗ Release build failed${NC}"
    exit 1
fi

# 5. Check dependency updates
echo ""
echo "5. Checking for dependency updates..."
echo "  Running cargo update --dry-run..."
UPDATE_OUTPUT=$(cargo update --dry-run 2>&1)
if echo "$UPDATE_OUTPUT" | grep -q "Updating"; then
    echo -e "${YELLOW}⚠ Updates available for dependencies:${NC}"
    echo "$UPDATE_OUTPUT" | grep "Updating" | head -10 | sed 's/^/    /'
    echo ""
    if ! confirm "Dependencies have updates available. Continue anyway?"; then
        echo "Consider running 'cargo update' to update compatible versions."
        exit 1
    fi
else
    echo -e "${GREEN}✓ All dependencies are up to date${NC}"
fi

# Optional: Check with cargo-outdated if available
if command_exists cargo-outdated; then
    echo ""
    echo "  Checking for major version updates..."
    OUTDATED_COUNT=$(cargo outdated --depth 1 2>/dev/null | grep -c "^---" || echo "0")
    if [ "$OUTDATED_COUNT" -gt "1" ]; then
        echo -e "${YELLOW}Note: Major version updates may be available${NC}"
        cargo outdated --depth 1 | head -15
    fi
fi

# 6. Version check
echo ""
echo "6. Version information..."
CURRENT_VERSION=$(grep "^version" Cargo.toml | head -1 | cut -d'"' -f2)
echo "  Current version: $CURRENT_VERSION"
echo ""
echo "  Recent tags:"
git tag -l | tail -5 | sed 's/^/    /'

# 7. CHANGELOG check
echo ""
echo "7. Checking CHANGELOG..."
if [ -f CHANGELOG.md ]; then
    if grep -q "$CURRENT_VERSION" CHANGELOG.md; then
        echo -e "${GREEN}✓ Version $CURRENT_VERSION found in CHANGELOG.md${NC}"
    else
        echo -e "${YELLOW}Warning: Version $CURRENT_VERSION not found in CHANGELOG.md${NC}"
        if ! confirm "Continue anyway?"; then
            exit 1
        fi
    fi
else
    echo -e "${YELLOW}Warning: CHANGELOG.md not found${NC}"
fi

# 8. Release notes check
echo ""
echo "8. Checking release notes..."
echo -e "${YELLOW}Please ensure you have prepared comprehensive release notes including:${NC}"
echo "  - New features with descriptions"
echo "  - Bug fixes"
echo "  - Breaking changes (if any)"
echo "  - Installation/upgrade instructions"
echo "  - Acknowledgments"
echo ""
if ! confirm "Have you prepared release notes?"; then
    echo -e "${RED}Please prepare release notes before continuing.${NC}"
    echo "Example template:"
    echo "  - Summary of the release"
    echo "  - New Features section with details"
    echo "  - Bug Fixes section"
    echo "  - Installation instructions"
    exit 1
fi

# 9. TODO check
echo ""
echo "9. Checking for TODOs..."
TODO_COUNT=$(grep -r "TODO\|FIXME\|HACK\|XXX" --include="*.rs" src/ 2>/dev/null | wc -l | tr -d ' ')
if [ "$TODO_COUNT" -gt "0" ]; then
    echo -e "${YELLOW}Found $TODO_COUNT TODO/FIXME/HACK comments${NC}"
    if confirm "Show them?"; then
        grep -r "TODO\|FIXME\|HACK\|XXX" --include="*.rs" src/ | head -10
        if [ "$TODO_COUNT" -gt "10" ]; then
            echo "  ... and $((TODO_COUNT - 10)) more"
        fi
    fi
fi

# 10. Final confirmation
echo ""
echo -e "${BLUE}=== RELEASE SUMMARY ===${NC}"
echo "  Version: $CURRENT_VERSION"
echo "  Branch: $CURRENT_BRANCH"
echo "  Binary size: $BINARY_SIZE"
echo ""

if confirm "Ready to create release?"; then
    echo ""
    echo "Next steps:"
    echo "  1. Update CHANGELOG.md if needed"
    echo "  2. Commit any final changes"
    echo "  3. Run: git tag -a v$CURRENT_VERSION -m \"Release v$CURRENT_VERSION\""
    echo "  4. Run: git push origin main --tags"
    echo "  5. Create GitHub release with comprehensive release notes"
    echo "     gh release create v$CURRENT_VERSION --notes \"...\" "
    echo "  6. Run: cargo publish (if publishing to crates.io)"
else
    echo "Release cancelled."
fi