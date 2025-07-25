# TODO List for ftr

This file tracks planned work for the ftr project.

## High Priority

- [ ] Add FreeBSD support
- [ ] Add OpenBSD support  
- [x] Add Windows support (completed in v0.2.3)
- [ ] Add missing tests for complex logic
  - UDP socket error handling
  - ICMP packet parsing edge cases
  - ASN lookup failures

## Medium Priority

- [x] Print detected public IP address in output (completed in v0.2.2)
- [x] Use minimalist printing for silent hops (spaces instead of '[UNKNOWN]') (completed in v0.2.2)
- [x] Add structured JSON output option (--json) for programmatic use (completed in v0.2.2)
- [x] Add verbose mode (-v) to show which protocol/socket mode is being used (completed in v0.2.2)
- [ ] Complete socket abstraction implementation
  - Add TCP mode support (TCP SYN packets)
  - Add IPv6 support (ICMPv6, UDP6, TCP6)
  - Full UDP response handling on non-Linux platforms
  - Port selection option (-p/--port) for TCP/UDP
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

## Future Enhancements

- [ ] Add integration tests under `tests/` directory for end-to-end scenarios
- [ ] Add property-based tests (e.g. via `proptest`) for parsing & classification logic
- [ ] Define and expose Cargo feature flags for optional modules (async, dns, IPv6)
- [ ] Add fuzz testing to CI pipeline
- [ ] Add benchmarking suite (Criterion) under `benches/` to track performance regressions
- [ ] Add fuzz targets (e.g. using `cargo-fuzz`) for packet parsing components