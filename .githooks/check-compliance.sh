#!/bin/bash
# Run full compliance checks locally

set -e

# This runs the same checks as pre-push hook
# Use this to verify compliance before pushing

exec "$(dirname "$0")/pre-push"