# Git Hooks

This directory contains git hooks for the ftr project.

## Setup

The repository is already configured to use this hooks directory. If you clone this repository, you need to run:

```bash
git config core.hooksPath .githooks
```

## Available Hooks

### pre-commit (fast checks)

Runs before each commit to ensure code quality:

1. **rustfmt** - Checks that all Rust code is properly formatted
2. **clippy** - Runs clippy lints to catch common mistakes and improve code quality

If either check fails, the commit will be aborted. Tests are disabled by default for speed.

### pre-push (full compliance)

Runs before pushing to ensure full compliance with Rust best practices:

1. **rustfmt** - Code formatting check
2. **clippy** - Linting with warnings as errors
3. **tests** - All unit and integration tests
4. **documentation** - Ensures docs build without errors
5. **cargo-audit** - Security vulnerability check
6. **cargo-machete** - Unused dependency check
7. **cargo-outdated** - Reports outdated dependencies
8. **MSRV check** - Verifies minimum supported Rust version
9. **TODO check** - Reports TODO/FIXME comments in code

## Scripts

### check-compliance.sh

Run full compliance checks locally without pushing:
```bash
.githooks/check-compliance.sh
```

### release-checklist.sh

Interactive checklist to run before creating a release:
```bash
.githooks/release-checklist.sh
```

### install-tools.sh

Install recommended development tools:
```bash
.githooks/install-tools.sh
```

## Manual Fixes

- To fix formatting issues: `cargo fmt`
- To see clippy warnings: `cargo clippy`
- To run tests: `cargo test`
- To check security: `cargo audit`
- To check unused deps: `cargo machete`
- To check outdated deps: `cargo outdated`