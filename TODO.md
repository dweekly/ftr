# TODO List for ftr

This file tracks planned work for the ftr project.

## Architectural Improvements

- [ ] **Refactor to Eliminate Global Caches (Handle Pattern)**: Implement the `Ftr` struct to own all caches and resources, removing global static variables. This will improve testability, flexibility, and code clarity. See `docs/HANDLE_PATTERN_REFACTOR.md` for the detailed plan.
- [ ] **Remove "async" naming throughout codebase**: Since v0.4.0 removed all sync code, rename modules and types to remove redundant "async" qualifiers (e.g., `async_api.rs` → `api.rs`, `AsyncTraceroute` → `Traceroute`, `FullyParallelAsyncEngine` → `FullyParallelEngine`, etc.)

## High Priority

- [x] Enhanced path segment labeling (completed in v0.6.0)
  - Added TRANSIT and DESTINATION segments replacing BEYOND
  - Public IPs without ASN info now classified as TRANSIT (IXPs, peering points)
  - Destination ASN looked up early and displayed in output

## Medium Priority

- [ ] **IXP/Peering Point Detection (v0.7.0 candidate)**
  - Systematically identify Internet Exchange Points in traceroute paths
  - Integrate PeeringDB API for IXP prefix and membership data
  - Analyze reverse DNS patterns (e.g., "equinix-sj", "ams-ix")
  - Add new SegmentType::Ixp for exchange points
  - See `docs/IXP_DETECTION_PROPOSAL.md` for detailed implementation plan
- [ ] **WHOIS fallback for network ownership (v0.6.1 candidate)**
  - When ASN lookup fails, use WHOIS to identify network owner
  - Aggressive caching by CIDR blocks (30+ day TTL, ownership rarely changes)
  - Helps identify IXPs (Equinix, AMS-IX, etc.) and peering points
  - Example: 206.223.116.16 has no ASN but WHOIS shows Equinix ownership
  - See `docs/WHOIS_ENHANCEMENT_PROPOSAL.md` for detailed design
- [ ] Add platform and timestamp to JSON output
  - Add `platform` field (e.g., "freebsd", "openbsd", "macos", "linux", "windows")
  - Add `timestamp` field with ISO 8601 format of when traceroute started
  - Consider adding `platform_version` for OS version information
- [ ] Add optional disk cache for DNS/ASN lookups
  - Cache DNS reverse lookups and ASN information to disk
  - Use a simple SQLite database or JSON file
  - Configurable TTL for cached entries
  - Option to clear cache via CLI flag
  - Share cache across traceroute runs for faster enrichment
- [ ] Replace libc with nix crate
  - nix provides safer, more idiomatic Rust bindings to system calls
  - Better error handling and type safety
  - More consistent cross-platform behavior
- [ ] Complete socket abstraction implementation
  - Add TCP mode support (TCP SYN packets)
  - Add IPv6 support (ICMPv6, UDP6, TCP6)
  - Full UDP response handling on non-Linux platforms
- [ ] Windows-specific improvements
  - Add UDP mode support for Windows
  - Add Windows-specific integration tests
  - Create MSI installer for Windows
  - Test on Windows 10 (currently tested on Windows 11)

## Low Priority

- [ ] Performance optimizations
  - Add benchmarks using criterion
  - Profile and optimize hot paths
  - Consider using `bytes` crate for zero-copy networking
- [ ] FreeBSD enhancements
  - Test on FreeBSD 13.x (currently tested on 14.3)
  - Consider adding to FreeBSD ports collection

## Future Enhancements

- [ ] Add integration tests under `tests/` directory for end-to-end scenarios
- [ ] Add property-based tests (e.g. via `proptest`) for parsing & classification logic
- [ ] Define and expose Cargo feature flags for optional modules (async, dns, IPv6)
- [ ] Add fuzz testing to CI pipeline
- [ ] Add benchmarking suite (Criterion) under `benches/` to track performance regressions
- [ ] Add fuzz targets (e.g. using `cargo-fuzz`) for packet parsing components
- [ ] Add test coverage tracking to CI (cargo-tarpaulin)
- [ ] Create test fixtures and mock implementations for external dependencies

## v0.4.0 Release Ideas

- [ ] Auto-updating traceroute mode
  - Re-run traceroute every few seconds automatically
  - Use terminal control (curses/TUI) to update display in place
  - Show patterns of how responses change over time
  - Highlight new sources of latency or packet loss
  - Track jitter and packet loss statistics
  - Visual indicators for route changes
  - Option to log changes to file for later analysis