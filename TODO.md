# TODO List for ftr

This file tracks planned work for the ftr project.

## High Priority

- [ ] Add missing tests for complex logic
  - UDP socket error handling
  - ICMP packet parsing edge cases
  - ASN lookup failures
  - Mock-based engine tests (timeout scenarios, destination detection)
  - Error path testing (socket creation failures, DNS failures)
- [ ] Increase test coverage to 50%+ (currently ~11%)
  - Add integration tests for library API
  - Add property-based tests for parsers
  - Test concurrent operations and edge cases

## Medium Priority

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