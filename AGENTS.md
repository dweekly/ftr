# Instructions for AI Agents

This document contains important guidelines and information for AI agents working with the ftr (Fast TRaceroute) codebase.

## Initial Setup

### Installing Git Hooks
**IMPORTANT**: Git hooks must be installed to prevent issues that would fail in CI:
```bash
# Option 1: Install hooks via symlinks
./.githooks/install-hooks.sh

# Option 2: Configure git to use .githooks directory
git config core.hooksPath .githooks
```

Without these hooks, code with formatting issues or clippy warnings can be committed and will fail in GitHub Actions CI.

## Critical Safety Rules

### Git Commands to NEVER Run
- **NEVER run `git reset`** - This can lose work and is too dangerous. Ask the user to run it if needed.
- **NEVER run `git push --force`** - This can overwrite remote history.
- **NEVER run `git rebase -i`** - Interactive commands don't work in non-interactive environments.
- **NEVER modify `.git/config`** - The user has specifically configured their git settings.

### System Commands to NEVER Run
- **NEVER run commands with `sudo`** - The AI agent cannot execute sudo commands. If elevated privileges are needed, ask the user to run the command instead.

### File and Data Operations to NEVER Perform
- **NEVER delete files without explicit user approval** - This includes:
  - Local files on any system
  - Remote files (S3, R2, cloud storage, servers)
  - Database records
  - Any data that cannot be easily recovered
- **When testing APIs or permissions**:
  - Only use read operations (list, get, describe)
  - Create test files with clearly temporary names (e.g., `test-temp-can-delete-*.txt`)
  - Never delete existing files "just to test" delete permissions
  - Always ask for permission before any destructive operation

## Environment Configuration

### Building on Windows with Parallels Mount
When building on Windows where the source directory is a Parallels mount (e.g., Y:\), you MUST use the `--target-dir` flag to specify a local Windows directory for the build artifacts. The Parallels filesystem doesn't handle temporary file operations correctly, causing "The parameter is incorrect. (os error 87)" errors.

**Correct build command:**
```bash
cargo build --target-dir C:/temp/ftr-target
```

### Windows 'nul' File Warning
**IMPORTANT**: When working on Windows, be careful not to accidentally create a file named 'nul'. This can happen if you run a command like `command > nul` without the proper syntax. Windows treats 'nul' as a special device name (like /dev/null on Unix).

If you accidentally create a 'nul' file:
- It should be deleted immediately
- It's already in .gitignore to prevent accidental commits
- Use `del nul` on Windows or `rm nul` on Unix to remove it

**Important notes:**
- Use forward slashes (/) not backslashes (\) in the path - they work on Windows and avoid escaping issues
- The `--target-dir` flag must be used directly with cargo; setting CARGO_TARGET_DIR environment variable doesn't work reliably
- DO NOT create .cargo/config.toml in the shared directory as it would affect macOS builds
- The built executable will be at: `C:/temp/ftr-target/debug/ftr.exe`

**Alternative methods that also work:**

From PowerShell directly:
```powershell
$env:CARGO_TARGET_DIR="C:\temp\ftr-target"; cargo build
```

From bash calling PowerShell:
```bash
powershell -Command '$env:CARGO_TARGET_DIR="C:\temp\ftr-target"; cargo build'
```

**What doesn't work:**
- `set CARGO_TARGET_DIR=C:\temp\ftr-target && cargo build` - environment variable not picked up by cargo in same command
- `cmd /c "set CARGO_TARGET_DIR=C:\temp\ftr-target && cargo build"` - variable doesn't persist to cargo
- Using backslashes in paths with --target-dir flag - causes parsing issues

### Running Tests on Windows

When running tests on Windows in some environments (like Parallels VMs), you may encounter an issue where `cargo test` reports "0 tests run" with all tests filtered out. This happens when cargo passes an unexpected filter argument (like "2") to test binaries.

**Test commands that work:**
```bash
# Pass an empty filter string to avoid the default filter
cargo test --target-dir C:/temp/ftr-target -- ""

# Use --nocapture flag (prevents the filter issue)
cargo test --target-dir C:/temp/ftr-target -- --nocapture

# Run a specific test suite
cargo test --target-dir C:/temp/ftr-target --test windows_integration

# Use the provided helper script
./run-tests.ps1
```

**Note**: This filter issue appears to be environment-specific and may not affect all Windows systems.

### ENVIRONMENT.md
Each development environment should have an `ENVIRONMENT.md` file that contains environment-specific configuration. This file is NOT checked into version control and is listed in `.gitignore`.

If `ENVIRONMENT.md` doesn't exist, create it using the following schema:

```markdown
# Environment Configuration

This file contains environment-specific configuration and is NOT checked into version control.

## Host System
- **OS**: [Operating system name and version]
- **Platform**: [Platform identifier, e.g., darwin, linux, windows]
- **Working Directory**: [Full path to project directory]
- **Available Tools**: 
  - [List of relevant tools and their versions]

## Virtual Machines
[For each VM, include:]

### [VM Name]
- **OS**: [Operating system and version]
- **IP**: [IP address if applicable]
- **Username**: [Username for SSH/access]
- **SSH Key**: [Path to SSH key or access method]
- **SSH Command**: [Complete SSH command to connect]
- **Shared Directory**: [Any shared/mounted directories]
- **Purpose**: [What this VM is used for]
- **Status**: [Configured/Not yet configured]

## Git Configuration
- **Current Branch**: [Current git branch]
- **Main Branch**: [Default branch for PRs]
- **Remote**: [Remote repository location]

## Project-Specific Notes
[Any environment-specific notes, constraints, or configurations]
```

Always check for `ENVIRONMENT.md` when starting work and use it to understand:
- How to access VMs for testing
- What tools are available
- Any environment-specific constraints

## Project-Specific Guidelines

### Socket Abstraction Architecture
The project uses a multi-mode socket abstraction layer located in `src/socket/`:
- `mod.rs` - Core traits and types
- `factory.rs` - Socket factory with automatic fallback
- `icmp_v4.rs` - ICMP implementations
- `udp.rs` - UDP implementations (including Linux IP_RECVERR support)

### Error Handling
- Use OS error codes (EPERM=1, EACCES=13) instead of string matching for permission errors
- Check `io_err.raw_os_error()` for specific error codes

### Testing and Validation
- Always run `cargo fmt` before committing
- Always run `cargo clippy -- -D warnings` before committing (this matches GitHub Actions CI)
- Pre-commit hooks are configured in `.githooks/` - they run automatically
- Always run `cargo audit` after adding new modules or dependencies to catch security vulnerabilities early
- Always run `cargo outdated` before cutting a release to ensure dependencies are up to date
- **IMPORTANT**: GitHub Actions uses `cargo clippy -- -D warnings` which treats all warnings as errors

### Platform-Specific Code
- Use `#[cfg(target_os = "linux")]` for Linux-specific features
- The project supports Linux IP_RECVERR for UDP traceroute without root

### Commit Guidelines
- Use clear, descriptive commit messages
- Include the robot emoji and Claude Code attribution:
  ```
  🤖 Generated with [Claude Code](https://claude.ai/code)
  
  Co-Authored-By: Claude <noreply@anthropic.com>
  ```

### Command References
- Format code: `cargo fmt`
- Check formatting: `cargo fmt -- --check`
- Run linter: `cargo clippy -- -D warnings` (matches CI)
- Run tests: `cargo test`
- Build project: `cargo build`
- Run the binary: `sudo target/debug/ftr <hostname>`
- Check full compliance: `.githooks/check-compliance.sh`
- Release checklist: `.githooks/release-checklist.sh`
- Install dev tools: `.githooks/install-tools.sh`

### Important Files
- `Cargo.toml` - Dependencies and project metadata
- `src/main.rs` - Main entry point and CLI
- `src/socket/` - Socket abstraction layer
- `docs/MULTI_MODE.md` - Documentation for multi-mode probing
- `.githooks/pre-commit` - Pre-commit hook for formatting and linting

### Current Development Status
- v0.2.0 - Released with basic functionality
- v0.2.1 - Released with:
  - Socket abstraction layer with automatic fallback
  - Multi-mode support (Raw ICMP, DGRAM ICMP, UDP)
  - Linux IP_RECVERR support for privilege-free UDP traceroute
  - Multiple probes per TTL (-q/--queries option)
  - Improved error handling and diagnostics

### Known Limitations
- UDP mode requires either root privileges or Linux IP_RECVERR
- IPv6 support is not yet implemented
- TCP mode is not yet implemented
- Basic UDP socket (without ICMP reception) is non-functional and removed

## Git Best Practices

### File Operations
- **Always use git commands for file operations**:
  - Use `git mv` instead of deleting and recreating files
  - Use `git rm` to remove files
- **Never create test files or new versions of files directly** - create a branch for experiments and either discard or merge it
- **Ensure the directory is git clean before committing** - no untracked files or directories should remain

### Development Workflow
- **Always work on feature branches** - never commit new features directly to main
  - Create branches like `feature/v0.2.2` or `feature/json-output`
  - Merge to main only when feature is complete and tested
- **Keep commits small and well-scoped** - each commit should do one thing
- **Track work in TODO.md** - when new issues arise while working on something else, add them to TODO.md
- **Update TODO.md when completing work** - remove completed items
- **Update CHANGELOG.md** for notable or user-facing changes
- **Update README.md** if the project definition or scope changes
- **Run compliance checks before pushing** - use `.githooks/check-compliance.sh` to verify locally
- **Use release checklist** - run `.githooks/release-checklist.sh` before creating releases
- **NEVER check in untested code** - always verify scripts, configurations, and code changes work as expected before committing them

### Code Quality
- **Always write tests alongside code** - ensure tests pass in the commit hook
- **Avoid code duplication** - refactor common patterns
- **After each commit, review for refactoring opportunities**
- **Keep files small and modular** - each file should have a clear, single purpose
- **Use consistent naming** - follow Rust naming conventions (snake_case for functions/variables, CamelCase for types)
- **Comment complex logic** - make code easy to reason about

### Tool Requests
- **Feel free to ask for tools** - if you need tools like ripgrep to work more effectively, ask the user to install them

### Release Process
- **Before cutting any release**:
  1. Run `.githooks/release-checklist.sh` to ensure all checks pass
  2. Ensure `cargo outdated` shows all dependencies are up to date
  3. Update CHANGELOG.md with release notes
  4. Verify version number in Cargo.toml
  5. Ensure all tests pass and no TODO/FIXME items are critical
  6. **Prepare comprehensive release notes** including:
     - Summary of the release
     - New features with detailed descriptions
     - Bug fixes
     - Breaking changes (if any)
     - Installation/upgrade instructions
     - Acknowledgments
- **The release checklist script automatically**:
  - Checks git status and branch
  - Runs all compliance checks (format, clippy, tests, docs)
  - Runs security audit
  - Checks for outdated dependencies
  - Builds release binary and reports size
  - Validates CHANGELOG.md entries
  - **Prompts for release notes confirmation** (added in v0.2.2)
- **Creating the GitHub release**:
  - Use `gh release edit` to add comprehensive notes after tag is pushed
  - Include installation instructions for different platforms
  - Highlight major features and improvements
  - Provide clear upgrade path from previous versions

### Creating Pull Requests with GitHub CLI
- **Always use `--head` flag when creating PRs**:
  ```bash
  gh pr create --base main --head branch-name --title "Title" --body "Description"
  ```
- **Common issue**: Without `--head`, gh pr may fail with "aborted: you must first push the current branch"
- **Even after pushing**, gh pr sometimes requires explicit `--head` flag
- **Example workflow**:
  ```bash
  # Push your branch
  git push -u origin feature-branch
  
  # Create PR with explicit base and head
  gh pr create --base main --head feature-branch \
    --title "Add new feature" \
    --body "Description of changes"
  ```

## Virtual Machine Guidelines

### Shared Directory Access
- **IMPORTANT**: The ftr directory is mounted at `/media/psf/ftr` in VMs - DO NOT copy files to/from the VM
- The mounted directory is shared between host and VM, so any changes are immediately visible in both places
- Access files directly from the mount point - no need for scp, rsync, or file copying
- Example: To run tests on Linux VM, just `ssh -i ~/.ssh/ftr_vm_key ftr@<VM_IP> "cd /media/psf/ftr && ./scripts/test.sh"`

### VM Development Workflow
- Build on the target platform (e.g., build Linux binaries on Linux VM)
- Use the shared mount to access source code and scripts (except FreeBSD - see note below)
- Results and outputs are immediately available on both host and VM

### Platform-Specific Testing
- **CRITICAL**: Always test platform-specific code on the target VM before pushing
- Platform-specific tests (e.g., `#[cfg(target_os = "freebsd")]`) are NOT compiled or run on other platforms
- Before pushing changes that include platform-specific code:
  1. Copy/sync the code to the target VM
  2. Run `cargo test --all` on the VM
  3. Verify the specific functionality works as expected
- Example: FreeBSD-specific tests will only compile and run on FreeBSD, not on macOS/Linux

### FreeBSD VM Special Notes
- **No Parallels Tools support**: FreeBSD VMs do not have shared directory support
- Must use `scp`, `rsync`, or `tar` to transfer files
- Example workflow:
  ```bash
  # Using rsync (preferred if available)
  rsync -avz --exclude target --exclude .git -e "ssh -i ~/.ssh/ftr_vm_key" . ftr@192.168.53.178:~/ftr/
  
  # Or using tar
  tar -czf /tmp/ftr-latest.tar.gz --exclude target --exclude .git .
  scp -i ~/.ssh/ftr_vm_key /tmp/ftr-latest.tar.gz ftr@192.168.53.178:~/
  ssh -i ~/.ssh/ftr_vm_key ftr@192.168.53.178 'cd ~/ && tar -xzf ftr-latest.tar.gz -C ~/ftr/'
  
  # Run tests on FreeBSD
  ssh -i ~/.ssh/ftr_vm_key ftr@192.168.53.178 'cd ~/ftr && cargo test --all'
  ```

### CI Environment Notes
- **GitHub Actions FreeBSD runner runs as root**: The vmactions/freebsd-vm action runs as root user
  - Non-root error tests need to check if running as root first
  - sudo is not installed by default on the FreeBSD CI runner
  - CI scripts should use conditional logic: if root, run directly; otherwise use sudo

## Tool Usage Guidelines

### Bash Tool Command Execution on Windows
**IMPORTANT**: On Windows, the Bash tool passes arguments directly to the command executable, it does NOT interpret shell syntax like redirections or pipes.

**Common mistake on Windows**:
```bash
# WRONG - This will fail with "unexpected argument '2' found" on Windows
Bash(cargo build --features async 2>&1 | grep -E "(warning|error)")
```

**Correct approaches for Windows**:
```bash
# Option 1: Use PowerShell (preferred on Windows)
Bash(powershell -c "cargo build --features async 2>&1 | Select-String 'warning|error'")

# Option 2: Use cmd.exe with proper syntax
Bash(cmd /c "cargo build --features async 2>&1 | findstr /R warning error")

# Option 3: Let the output come through naturally without filtering
Bash(cargo build --features async)
```

**Why this happens on Windows**: The Bash tool on Windows executes commands directly (like `CreateProcess`) rather than through a shell. This means:
- Shell redirections (`>`, `<`, `2>&1`) are passed as literal arguments to the program
- Pipes (`|`) are passed as literal arguments instead of creating a pipeline
- Environment variables (`%VAR%` or `$VAR`) are not expanded
- Command substitution doesn't work

**Windows-specific notes**:
- Use PowerShell (`powershell -c "..."`) for complex commands with pipes and redirections
- Use `cmd /c "..."` if you need traditional Windows command syntax
- For simple commands without shell features, call them directly
- Remember that Windows uses backslashes for paths, but forward slashes often work too

## General Best Practices
1. Always read files before editing them
2. Check for existing patterns and follow them
3. Run tests after making changes
4. Keep changes focused and atomic
5. Document significant changes
6. Ask the user before making destructive operations
7. NEVER use `--no-verify` when pushing - always let pre-push hooks run

## Documentation Index

This section provides a comprehensive list of all documentation files and their purposes to help future agents understand which documents to read for specific use cases.

### Root-Level Documentation

- **README.md** - Main project documentation with features, installation instructions, usage examples, and build instructions
- **CHANGELOG.md** - Comprehensive history of all releases with detailed notes on features, fixes, and breaking changes
- **LICENSE** - MIT license terms
- **TODO.md** - Active development tasks and future features
- **AGENTS.md** - (This file) Instructions and guidelines for AI agents working with the codebase
- **ENVIRONMENT.md** - Local environment configuration (not in version control)

### docs/ Directory

#### Development and Process Documentation
- **docs/RUST_BEST_PRACTICES.md** - Rust-specific best practices for the project including error handling, documentation, testing, and code organization
- **docs/RELEASE_CHECKLIST.md** - Comprehensive checklist for creating releases including version updates, testing, and GitHub release creation

#### Technical Documentation
- **docs/LIBRARY_USAGE.md** - Comprehensive guide for using ftr as a Rust library including API examples, configuration options, and integration patterns
- **docs/UDP_TRACEROUTE_LINUX.md** - Explains UDP traceroute behavior on Linux, port filtering issues, and how ftr solves them
- **docs/MULTI_MODE.md** - Documentation for multi-mode probing feature including multiple queries per hop and load-balanced path discovery
- **docs/PACKAGING.md** - Guide for packaging ftr for different platforms including Debian/Ubuntu, FreeBSD, macOS, and Windows
- **docs/TIMING_CONFIGURATION.md** - Describes the timing configuration system for eliminating hardcoded delays and enabling runtime performance tuning

### Platform-Specific Notes

#### Linux
- Read **docs/UDP_TRACEROUTE_LINUX.md** for UDP mode behavior and privilege requirements
- Check **docs/PACKAGING.md** for APT repository setup and .deb package creation

#### FreeBSD/OpenBSD
- See **README.md** installation sections for platform-specific build requirements
- Check **AGENTS.md** VM section for testing procedures (no shared directory support)

#### Windows
- See **AGENTS.md** for Parallels mount build issues and workarounds
- Check **README.md** for Windows-specific installation options

#### macOS
- See **docs/PACKAGING.md** for Homebrew tap information
- Check **README.md** for macOS installation via Homebrew

### Use Case Quick Reference

| Task | Read These Documents |
|------|---------------------|
| Understanding the project | README.md, CHANGELOG.md |
| Using ftr as a library | docs/LIBRARY_USAGE.md |
| Creating a new release | docs/RELEASE_CHECKLIST.md, CHANGELOG.md |
| Packaging for distribution | docs/PACKAGING.md |
| Understanding UDP behavior | docs/UDP_TRACEROUTE_LINUX.md |
| Working with VMs | AGENTS.md (VM Guidelines section), ENVIRONMENT.md |
| Following code standards | docs/RUST_BEST_PRACTICES.md, AGENTS.md |
| Planning new features | TODO.md, CHANGELOG.md (for context) |
| Multi-probe traceroute | docs/MULTI_MODE.md |
| Optimizing performance | docs/TIMING_CONFIGURATION.md |
