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
    BINARY_SIZE=$(ls -lh target/release/ftr | awk '{print $5}')
    echo "  Binary size: $BINARY_SIZE"
else
    echo -e "${RED}✗ Release build failed${NC}"
    exit 1
fi

# 5. Check outdated dependencies
echo ""
echo "5. Dependency status..."
if command_exists cargo-outdated; then
    OUTDATED=$(cargo outdated --format json 2>/dev/null | jq '.dependencies | map(select(.project != null)) | length' 2>/dev/null || echo "0")
    if [ "$OUTDATED" != "0" ]; then
        echo -e "${YELLOW}Warning: $OUTDATED direct dependencies are outdated${NC}"
        cargo outdated --depth 1
        if ! confirm "Continue with outdated dependencies?"; then
            exit 1
        fi
    else
        echo -e "${GREEN}✓ All direct dependencies up to date${NC}"
    fi
else
    echo -e "${YELLOW}Cannot check (cargo-outdated not installed)${NC}"
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

# 8. TODO check
echo ""
echo "8. Checking for TODOs..."
TODO_COUNT=$(grep -r "TODO\|FIXME\|HACK\|XXX" --include="*.rs" src/ 2>/dev/null | wc -l | tr -d ' ')
if [ "$TODO_COUNT" -gt "0" ]; then
    echo -e "${YELLOW}Found $TODO_COUNT TODO/FIXME/HACK comments${NC}"
    if confirm "Show them?"; then
        grep -r "TODO\|FIXME\|HACK\|XXX" --include="*.rs" src/ | head -10
        if [ "$TODO_COUNT" -gt "10" ]; then
            echo "  ... and $(($TODO_COUNT - 10)) more"
        fi
    fi
fi

# 9. Final confirmation
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
    echo "  5. Create GitHub release"
    echo "  6. Run: cargo publish (if publishing to crates.io)"
else
    echo "Release cancelled."
fi