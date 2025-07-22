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

## Best Practices
1. Always read files before editing them
2. Check for existing patterns and follow them
3. Run tests after making changes
4. Keep changes focused and atomic
5. Document significant changes
6. Ask the user before making destructive operations