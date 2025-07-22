# Instructions for AI Agents

This document contains important guidelines and information for AI agents working with the ftr (Fast TRaceroute) codebase.

## Critical Safety Rules

### Git Commands to NEVER Run
- **NEVER run `git reset`** - This can lose work and is too dangerous. Ask the user to run it if needed.
- **NEVER run `git push --force`** - This can overwrite remote history.
- **NEVER run `git rebase -i`** - Interactive commands don't work in non-interactive environments.
- **NEVER modify `.git/config`** - The user has specifically configured their git settings.

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
- Always run `cargo clippy` before committing
- Pre-commit hooks are configured in `.githooks/` - they run automatically

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
- Run linter: `cargo clippy`
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
- v0.2.1 - In development on `feature/v0.2.1-socket-abstraction` branch
  - Socket abstraction layer with automatic fallback
  - Multi-mode support (Raw ICMP, DGRAM ICMP, UDP)
  - Linux IP_RECVERR support for privilege-free UDP traceroute

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
- **Keep commits small and well-scoped** - each commit should do one thing
- **Track work in TODO.md** - when new issues arise while working on something else, add them to TODO.md
- **Update TODO.md when completing work** - remove completed items
- **Update CHANGELOG.md** for notable or user-facing changes
- **Update README.md** if the project definition or scope changes
- **Run compliance checks before pushing** - use `.githooks/check-compliance.sh` to verify locally
- **Use release checklist** - run `.githooks/release-checklist.sh` before creating releases

### Code Quality
- **Always write tests alongside code** - ensure tests pass in the commit hook
- **Avoid code duplication** - refactor common patterns
- **After each commit, review for refactoring opportunities**
- **Keep files small and modular** - each file should have a clear, single purpose
- **Use consistent naming** - follow Rust naming conventions (snake_case for functions/variables, CamelCase for types)
- **Comment complex logic** - make code easy to reason about

### Tool Requests
- **Feel free to ask for tools** - if you need tools like ripgrep to work more effectively, ask the user to install them

## General Best Practices
1. Always read files before editing them
2. Check for existing patterns and follow them
3. Run tests after making changes
4. Keep changes focused and atomic
5. Document significant changes
6. Ask the user before making destructive operations