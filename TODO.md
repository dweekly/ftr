# TODO List for ftr

This file tracks ongoing and planned work for the ftr project.

## High Priority

- [ ] Fix unwrap() usage warnings from clippy
  - Replace `.unwrap()` calls on Mutex locks with proper error handling
  - Consider using `.expect()` with descriptive messages for locks that should never fail
  - Update Cargo.toml to re-enable `unwrap_used = "warn"` after fixes

## Medium Priority

- [ ] Update pre-commit hook to optionally run cargo-audit
  - Add cargo-audit check (with option to skip for speed)
  - Document how to install cargo-audit in README

- [ ] Complete socket abstraction implementation
  - Add Raw ICMP socket implementation
  - Add IPv6 support
  - Add TCP mode support
  - Implement Linux IP_RECVERR for UDP mode

## Low Priority

- [ ] Consider adding cargo-machete for unused dependency detection
  - Evaluate if we have any unused dependencies
  - Add to optional development tools

- [ ] Performance optimizations
  - Add benchmarks using criterion
  - Profile and optimize hot paths
  - Consider using `bytes` crate for zero-copy networking

## Future Enhancements

- [ ] Add integration tests
- [ ] Add property-based testing for complex logic
- [ ] Consider adding feature flags for optional functionality
- [ ] Add GitHub Actions CI/CD pipeline
- [ ] Add code coverage tracking
- [ ] Consider supporting more platforms (Windows, BSD)

## Completed
- [x] Add Rust best practices documentation
- [x] Set up stricter clippy lints
- [x] Add pre-commit hooks for rustfmt and clippy
- [x] Add missing documentation for public items
- [x] Fix redundant closure warnings
- [x] Fix inefficient to_string warnings