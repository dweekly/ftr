#!/bin/bash
# Install Vagrant and Parallels plugin

set -euo pipefail

echo "=== Installing Vagrant for automated VM management ==="
echo

# Install Vagrant via Homebrew
if ! command -v brew &> /dev/null; then
    echo "Homebrew not found. Please install from https://brew.sh"
    exit 1
fi

echo "Installing Vagrant..."
brew install vagrant

echo
echo "Installing Vagrant Parallels plugin..."
vagrant plugin install vagrant-parallels

echo
echo "=== Installation complete! ==="
echo "Vagrant version:"
vagrant --version
echo
echo "Installed plugins:"
vagrant plugin list