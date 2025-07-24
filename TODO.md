# TODO List for ftr

This file tracks planned work for the ftr project.

## High Priority

- [ ] Add FreeBSD support
- [ ] Add OpenBSD support  
- [ ] Add Windows support
- [ ] Add missing tests for complex logic
  - UDP socket error handling
  - ICMP packet parsing edge cases
  - ASN lookup failures

## Medium Priority

- [ ] Print detected public IP address in output
- [ ] Use minimalist printing for silent hops (spaces instead of '[UNKNOWN]')
- [ ] Complete socket abstraction implementation
  - Add TCP mode support
  - Add IPv6 support
- [ ] Integrate `cargo-machete` for unused-dependency detection
  - Assess and remove truly unused dependencies
  - Add to developer tooling installation script

## Low Priority

- [ ] Performance optimizations
  - Add benchmarks using criterion
  - Profile and optimize hot paths
  - Consider using `bytes` crate for zero-copy networking

## Future Enhancements

- [ ] Add integration tests under `tests/` directory for end-to-end scenarios
- [ ] Add property-based tests (e.g. via `proptest`) for parsing & classification logic
- [ ] Define and expose Cargo feature flags for optional modules (async, dns, IPv6)
- [ ] Enhance CI (GitHub Actions) to include security audit (`cargo audit`), fuzz testing, and coverage checks
- [ ] Add code coverage reporting (via `cargo-tarpaulin` or `cargo-llvm-cov`)
- [ ] Add benchmarking suite (Criterion) under `benches/` to track performance regressions
- [ ] Add fuzz targets (e.g. using `cargo-fuzz`) for packet parsing components