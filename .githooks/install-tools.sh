#!/bin/bash
# Script to install recommended Rust development tools

echo "Installing recommended Rust tools for ftr development..."

# Check if cargo is available
if ! command -v cargo &> /dev/null; then
    echo "Error: cargo not found. Please install Rust first."
    exit 1
fi

# Function to install a cargo tool if not already installed
install_if_missing() {
    local tool=$1
    local package=$2
    
    if ! command -v "$tool" &> /dev/null; then
        echo "Installing $package..."
        cargo install "$package"
    else
        echo "$package is already installed"
    fi
}

# Install tools
install_if_missing "cargo-audit" "cargo-audit"
install_if_missing "cargo-outdated" "cargo-outdated"
install_if_missing "cargo-machete" "cargo-machete"

# Check for shellcheck
echo ""
if ! command -v shellcheck &> /dev/null; then
    echo "shellcheck is not installed."
    echo "To install shellcheck:"
    echo "  - macOS: brew install shellcheck"
    echo "  - Ubuntu/Debian: sudo apt-get install shellcheck"
    echo "  - Fedora: sudo dnf install shellcheck"
    echo "  - Arch: sudo pacman -S shellcheck"
else
    echo "shellcheck is already installed"
fi

echo ""
echo "All recommended tools installed!"
echo "You can now use:"
echo "  - cargo audit      : Check for security vulnerabilities"
echo "  - cargo outdated   : Check for outdated dependencies"
echo "  - cargo machete    : Check for unused dependencies"
echo "  - shellcheck       : Lint shell scripts for issues"
echo ""
echo "These tools are optional but recommended for maintaining code quality."