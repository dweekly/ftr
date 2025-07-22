# Git Hooks

This directory contains git hooks for the ftr project.

## Setup

The repository is already configured to use this hooks directory. If you clone this repository, you need to run:

```bash
git config core.hooksPath .githooks
```

## Available Hooks

### pre-commit

Runs before each commit to ensure code quality:

1. **rustfmt** - Checks that all Rust code is properly formatted
2. **clippy** - Runs clippy lints to catch common mistakes and improve code quality

If either check fails, the commit will be aborted.

## Manual Fixes

- To fix formatting issues: `cargo fmt`
- To see clippy warnings: `cargo clippy`