# TODO List for ftr

This file tracks ongoing and planned work for the ftr project.

## High Priority

- [x] Fix unwrap() usage warnings from clippy
  - Replaced all `.unwrap()` calls on Mutex locks with `.expect()` with descriptive messages
  - Fixed non-mutex unwraps with proper error handling
  - Re-enabled `unwrap_used = "warn"` in Cargo.toml

## Medium Priority

- [x] Enforce mandatory `cargo audit` in pre-push hook
- [x] Update AGENTS.md to remind agents to run `cargo audit` when adding new modules/dependencies

- [ ] Complete socket abstraction implementation
  - Add Raw ICMP socket implementation
  - Add IPv6 support
  - Add TCP mode support
  - Implement Linux IP_RECVERR for UDP mode

## Low Priority

- [ ] Integrate `cargo-machete` for unused-dependency detection
  - Assess and remove truly unused dependencies
  - Add to developer tooling installation script

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
- [ ] Consider official support for additional platforms (Windows, BSD)

## Completed
- [x] Add Rust best practices documentation
- [x] Set up stricter clippy lints
- [x] Add pre-commit hooks for rustfmt and clippy
- [x] Enforce cargo audit in pre-push hook and update AGENTS.md accordingly
- [x] Add missing documentation for public items
- [x] Fix redundant closure warnings
- [x] Fix inefficient to_string warnings
