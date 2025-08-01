# TODO List for ftr

This file tracks planned work for the ftr project.

## High Priority

- [x] Add missing tests for complex logic
  - UDP socket error handling
  - ICMP packet parsing edge cases
  - ASN lookup failures
  - Mock-based engine tests (timeout scenarios, destination detection)
  - Error path testing (socket creation failures, DNS failures)
- [x] Increase test coverage to 50%+ (achieved ~42% in v0.3.1)
  - Added integration tests for library API
  - Added tests for enrichment service, probe types, timing config, async API
  - Test concurrent operations and edge cases
- [x] Investigate test isolation for cache state
  - Implemented serial_test crate for cache-related tests
  - Tests now run serially to avoid cache conflicts
  - Fixed all flaky test failures due to concurrent cache access
- [ ] Enhanced path segment labeling
  - Add "TARGET" segment for hops in the same ASN as the destination
  - Consider renaming "BEYOND" to something more descriptive (e.g., "TRANSIT", "INTERNET", "BACKBONE")
  - Example: LAN → ISP → TRANSIT → TARGET (for hops within Google's network when tracing to 8.8.8.8)

## Medium Priority

- [ ] Add platform and timestamp to JSON output
  - Add `platform` field (e.g., "freebsd", "openbsd", "macos", "linux", "windows")
  - Add `timestamp` field with ISO 8601 format of when traceroute started
  - Consider adding `platform_version` for OS version information
- [x] Add async implementation for all platforms (completed in v0.3.1)
  - Async sockets for Windows, macOS, Linux, FreeBSD, OpenBSD
  - Immediate response processing without polling delays
  - Better performance especially for low-latency responses
- [ ] Remove sync implementation once all platforms have async
  - All platforms now have async implementation
  - Keep sync mode temporarily for backwards compatibility
  - Plan removal for v0.4.0
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