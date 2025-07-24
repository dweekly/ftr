#!/bin/bash
# Script to install git hooks by creating symlinks

set -e

# Get the git hooks directory
GIT_DIR=$(git rev-parse --git-dir)
HOOKS_DIR="$GIT_DIR/hooks"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Installing git hooks..."

# List of hooks to install
HOOKS=(
    "pre-commit"
    "pre-push"
)

# Create symlinks for each hook
for hook in "${HOOKS[@]}"; do
    if [ -f "$SCRIPT_DIR/$hook" ]; then
        # Remove existing hook if it exists
        if [ -e "$HOOKS_DIR/$hook" ]; then
            echo "Removing existing $hook hook..."
            rm -f "$HOOKS_DIR/$hook"
        fi
        
        # Create symlink
        echo "Installing $hook hook..."
        ln -sf "$SCRIPT_DIR/$hook" "$HOOKS_DIR/$hook"
        chmod +x "$HOOKS_DIR/$hook"
    else
        echo "Warning: $hook not found in $SCRIPT_DIR"
    fi
done

# Alternative: Configure git to use .githooks directory
echo ""
echo "Alternatively, you can configure git to use the .githooks directory directly:"
echo "  git config core.hooksPath .githooks"
echo ""
echo "Git hooks installed successfully!"
echo ""
echo "Hooks installed:"
for hook in "${HOOKS[@]}"; do
    if [ -L "$HOOKS_DIR/$hook" ]; then
        echo "  ✓ $hook"
    fi
done