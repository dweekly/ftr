# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**ftr** (Fast TRaceroute) is a high-performance parallel ICMP traceroute written in Rust. It sends probes concurrently for ~10x speedup over traditional traceroute, with automatic ASN lookup, reverse DNS, public IP detection via STUN, and network segment classification. Available as both a CLI tool and a Rust library. Cross-platform: Linux, macOS, Windows, FreeBSD, OpenBSD.

- **Version**: 0.6.0
- **MSRV**: 1.82.0
- **Rust Edition**: 2021
- **License**: MIT
- **Repo**: github.com/dweekly/ftr

## Build & Test Commands

```bash
cargo build                              # Debug build
cargo build --release                    # Release build (LTO, stripped)
cargo test                               # All tests
cargo test --lib                         # Unit tests only
cargo test <test_name>                   # Single test by name
cargo test --test <file>                 # Single integration test file
cargo fmt -- --check                     # Check formatting (CI enforced)
cargo clippy -- -D warnings             # Lint — warnings are errors in CI
cargo audit                              # Security vulnerability check
cargo machete                            # Unused dependency check
cargo doc --no-deps --all-features       # Build docs (RUSTDOCFLAGS=-Dwarnings in CI)
cargo bench                              # Benchmarks (criterion)
sudo cargo run -- google.com             # Run CLI (requires root on Unix)
sudo cargo run -- --json --max-hops 20 google.com  # JSON output
```

### Git Hooks (required)

Install before committing — they enforce fmt and clippy locally:
```bash
git config core.hooksPath .githooks
```

### Compliance & Release Scripts

```bash
.githooks/check-compliance.sh            # Full local compliance check
.githooks/release-checklist.sh           # Pre-release validation
.githooks/install-tools.sh               # Install dev tools (audit, machete, etc.)
```

## Architecture

### Core Modules (`src/`)

- **`traceroute/`** — Engine: async probe sending, parallel execution, config, result types, segment classification (LAN/ISP/TRANSIT/DESTINATION), ISP detection
- **`socket/`** — Platform-abstracted socket layer with automatic fallback (Raw ICMP -> DGRAM -> privileged UDP). Each platform has its own implementation file (`linux_async.rs`, `macos_async.rs`, `bsd_async.rs`, `windows_async_tokio.rs`). Factory pattern in `async_factory.rs`
- **`asn/`** — ASN lookup via WHOIS API with in-memory cache
- **`dns/`** — Reverse DNS via hickory-resolver with in-memory cache
- **`public_ip/`** — Public IP detection via STUN protocol with cache
- **`enrichment/`** — Parallel enrichment service (ASN + DNS lookups on hop results)
- **`services.rs`** — Service container owning ASN, DNS, STUN services
- **`caches.rs`** — Cache management
- **`config/`** — Configuration types and builder
- **`main.rs`** — CLI entry point (clap)
- **`lib.rs`** — Library public API

### Key Patterns

- **Services container**: `Services` struct owns all external service clients; `Ftr` handle wraps it for the high-level API
- **Socket fallback chain**: Factory tries socket types in order based on platform and permissions; uses `#[cfg(target_os)]` for platform-specific code
- **Shared caches**: In-memory caches for DNS, ASN, and STUN results shared across probes
- **Error codes over strings**: Permission errors use OS error codes (EPERM=1, EACCES=13), not string matching

### Platform Differences

| Platform | Socket Mode | Root Required | Notes |
|----------|-------------|---------------|-------|
| macOS    | Raw ICMP    | Yes           | Raw socket access |
| Linux    | Raw/DGRAM/UDP | No (UDP via IP_RECVERR) | Unprivileged UDP traceroute supported |
| FreeBSD/OpenBSD | Raw ICMP | Yes | Requires root for all operations |
| Windows  | Win32 ICMP API | No | Uses IcmpSendEcho, not raw sockets |

## CI Pipeline

GitHub Actions runs on push/PR to main: tests (Ubuntu stable + MSRV 1.82.0, macOS, Windows), formatting, clippy, code coverage (tarpaulin -> Codecov), security audit, unused deps (machete), outdated deps, doc build, and FreeBSD VM tests.

## Clippy Configuration

Defined in `Cargo.toml` under `[lints.clippy]`: correctness and suspicious lints are denied, `unwrap_used` warns (use `expect()` instead), `module_name_repetitions` is allowed, public items require docs (`missing_docs = "warn"`).

## Safety Rules

- **Never run `sudo`** — ask the user to run privileged commands
- **Never run `git reset` or `git push --force`**
- **Never modify `.git/config`**
- **Never delete files without explicit user approval** (local or remote)
- **Never use `--no-verify`** when committing or pushing
- **Always run `cargo fmt` and `cargo clippy -- -D warnings` before committing**
- Platform-specific tests (`#[cfg(target_os = "...")]`) are only compiled on the target platform — test on the actual platform before pushing platform-specific changes

## Windows Build Notes

When building on Windows where the source directory is a Parallels mount, use `--target-dir` to specify a local Windows directory:
```bash
cargo build --target-dir C:/temp/ftr-target
```

For tests on Windows (filter issue workaround):
```bash
cargo test --target-dir C:/temp/ftr-target -- ""
```

The Bash tool on Windows executes commands directly (not through a shell) — use `powershell -c "..."` for pipes, redirections, or environment variable expansion.

## VM Testing

- **Linux/Ubuntu**: Source directory is mounted at `/media/psf/ftr` in Parallels VMs — access files directly, don't copy
- **FreeBSD**: No Parallels Tools support — must use `rsync` or `scp` to transfer files
- **GitHub Actions FreeBSD**: Runs as root via vmactions/freebsd-vm; sudo is not installed

## Release Process

See `docs/RELEASE_PROCESS.md` for the full secure release workflow. Key steps:
1. Update version in `Cargo.toml` and `CHANGELOG.md`
2. Create release branch, PR to main
3. After merge, tag and push — automated validation and artifact building follow
4. Run `.githooks/release-checklist.sh` before any release

## Related Projects

**SwiftFTR** (`~/dev/SwiftFTR`) is a parallel Swift 6 implementation with more advanced features: bufferbloat testing, multipath/ECMP discovery, TCP/UDP/HTTP probes, comprehensive DNS client (11 record types), and a streaming traceroute API. It's the core of the Network Weather app. Use it as a reference for feature design and roadmap priorities.

## Documentation Conventions

- No docs should be backward-looking except CHANGELOG. Delete completed items from plans/TODOs rather than marking them done — git has the history.
- Every .md file in the project must be linked from the Documentation table in README.md (no orphaned docs).
