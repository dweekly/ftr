# Rust Best Practices for ftr

This document outlines additional Rust best practices that should be incorporated into the ftr project workflow.

## Current Practices (Already Implemented)
- ✅ `cargo fmt` - Code formatting
- ✅ `cargo clippy` - Linting with warnings as errors
- ✅ `cargo test` - Unit testing
- ✅ Pre-commit hooks for automated checks

## Recommended Additional Practices

### 1. Security Auditing
**Tool**: `cargo-audit`
- Checks dependencies for known security vulnerabilities
- Should run in CI and optionally in pre-commit

```bash
cargo install cargo-audit
cargo audit
```

### 2. Dependency Management
**Tool**: `cargo-outdated`
- Identifies outdated dependencies
- Helps maintain up-to-date and secure dependencies

```bash
cargo install cargo-outdated
cargo outdated
```

### 3. Unused Dependencies
**Tool**: `cargo-machete`
- Detects unused dependencies in Cargo.toml
- Keeps the project lean

```bash
cargo install cargo-machete
cargo machete
```

### 4. Documentation Linting
**Built-in**: `rustdoc`
- Ensure all public items are documented
- Check documentation examples compile

```toml
# In Cargo.toml or .cargo/config.toml
[lints.rust]
missing_docs = "warn"
missing_debug_implementations = "warn"
```

### 5. Additional Clippy Lints
Enable more strict clippy lints in `Cargo.toml`:

```toml
[lints.clippy]
# Correctness
correctness = "deny"
suspicious = "deny"

# Performance
perf = "warn"

# Style
style = "warn"
module_name_repetitions = "allow"  # Common in Rust

# Complexity
cognitive_complexity = "warn"

# Pedantic (selective)
needless_pass_by_value = "warn"
redundant_closure_for_method_calls = "warn"
inefficient_to_string = "warn"

# Restriction (very selective)
unwrap_used = "warn"
expect_used = "warn"
panic = "warn"
todo = "warn"
unimplemented = "warn"
```

### 6. Safety and Soundness
**Tool**: `cargo-careful`
- Runs with extra runtime checks for undefined behavior
- Useful during development and testing

```bash
cargo install cargo-careful
cargo careful test
```

### 7. Code Coverage
**Tool**: `cargo-tarpaulin` (Linux) or `cargo-llvm-cov`
- Measures test coverage
- Helps identify untested code paths

```bash
cargo install cargo-tarpaulin
cargo tarpaulin --out Html
```

### 8. Benchmarking
**Built-in**: Criterion or built-in bench
- Track performance regressions
- Especially important for performance-critical code like traceroute

```toml
[dev-dependencies]
criterion = "0.5"

[[bench]]
name = "traceroute_bench"
harness = false
```

### 9. MSRV (Minimum Supported Rust Version)
Define and check MSRV in `Cargo.toml`:

```toml
[package]
rust-version = "1.75.0"  # Example MSRV
```

### 10. Workspace Lints
If the project grows to multiple crates, use workspace-level lints:

```toml
[workspace.lints.clippy]
all = "warn"
```

## Cargo.toml Best Practices

### 1. Complete Metadata
- ✅ Already has: name, version, authors, description, license, repository
- Consider adding:
  - `rust-version` - MSRV
  - `exclude` - Files to exclude from package

### 2. Dependencies
- ✅ Using specific versions (good!)
- Consider:
  - Documenting why each dependency is needed
  - Regularly running `cargo update` and testing
  - Using `default-features = false` where possible

### 3. Feature Flags
For optional functionality:
```toml
[features]
default = ["async", "dns"]
async = ["tokio", "futures"]
dns = ["hickory-resolver"]
```

## Code Organization Best Practices

### 1. Module Structure
- Keep modules focused and single-purpose
- Use `pub(crate)` for internal APIs
- Prefer `mod.rs` for module organization

### 2. Error Handling
- Use `thiserror` for library errors
- Use `anyhow` for application errors (✅ already doing this)
- Consider custom error types for the library portion

### 3. Testing
- Unit tests next to code (✅ already doing)
- Integration tests in `tests/` directory
- Doc tests for examples
- Property-based testing with `proptest` for complex logic

### 4. Documentation
- All public items should have doc comments
- Include examples in doc comments
- Use `#![warn(missing_docs)]` at crate level

### 5. Type Safety
- Use newtype pattern for domain types
- Avoid primitive obsession
- Consider `NonZeroU32` etc. for values that can't be zero

## Performance Best Practices

### 1. Allocations
- Use `Vec::with_capacity` when size is known
- Consider `SmallVec` for small collections
- Use `&str` instead of `String` when possible

### 2. Async
- ✅ Already using tokio efficiently
- Consider using `tokio::select!` for concurrent operations
- Use `join!` instead of sequential `.await`s

### 3. Zero-Copy
- Use `bytes` crate for network buffers
- Avoid unnecessary clones
- Use `Cow<'_, str>` for sometimes-borrowed strings

## CI/CD Recommendations

### 1. GitHub Actions
```yaml
- cargo fmt -- --check
- cargo clippy -- -D warnings
- cargo test
- cargo audit
- cargo doc --no-deps
```

### 2. Release Checklist
- Update CHANGELOG.md
- Run `cargo semver-checks`
- Tag release
- `cargo publish --dry-run`

## Integration with Pre-commit

Update `.githooks/pre-commit` to include:
- `cargo audit` (optional, might be slow)
- Documentation checks
- MSRV check

## Gradual Adoption

Start with:
1. Security auditing (`cargo-audit`)
2. Stricter clippy lints
3. Documentation requirements

Then add:
4. Dependency management tools
5. Coverage tracking
6. Benchmarking

This ensures the codebase maintains high quality while not overwhelming development.