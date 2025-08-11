# Test Issues for v0.4.0 Release

## Problem Summary
The pre-push hook reports test failures, but tests pass when run individually or with constrained resources.

## Observed Behavior

### What Works
1. **Individual test suites pass**:
   - `cargo test --test error_handling_test` ✅
   - `cargo test --test integration_test` ✅
   - `cargo test --test caching_verification_test` ✅
   - `cargo test --lib` ✅
   
2. **Tests pass with resource constraints**:
   - `RUST_TEST_THREADS=1 cargo test` ✅
   - `RUST_TEST_THREADS=2 cargo test` ✅

3. **Tests pass on different platforms**:
   - macOS (Darwin) - passes with thread limits
   - Ubuntu 24.04 - passes with thread limits
   - Alpine Linux - library tests pass

### What Fails
1. **Full parallel test suite**: `cargo test` (default)
   - On macOS: Gets SIGKILL on caching_verification_test
   - On Ubuntu: Times out after 2 minutes during doc tests
   - Appears to be a resource contention or deadlock issue

2. **Pre-push hook**: Reports "Checking tests... ✗"
   - Runs `cargo test` which seems to hang or fail
   - Doesn't provide detailed error output

## Root Cause Analysis

### Likely Issues
1. **Resource contention in parallel tests**:
   - Multiple tests may be trying to bind to the same ports
   - Global state (caches) being accessed concurrently
   - Too many async runtime threads spawning

2. **Test interdependencies**:
   - Some tests clear global caches (ASN_CACHE, RDNS_CACHE)
   - Tests might interfere when run in parallel

3. **Platform-specific behavior**:
   - macOS: SIGKILL suggests memory or resource limits
   - Linux: Timeout suggests deadlock or infinite wait

### Specific Problem Tests
1. `caching_verification_test.rs` - Gets SIGKILL on macOS
2. Doc tests - Cause timeout on Ubuntu when run after other tests
3. `error_handling_test.rs` - Had platform-specific issues (fixed)

## Debugging Steps Needed

1. **Check for port conflicts**:
   - Review which tests create sockets
   - Ensure tests use different ports or serialize socket creation

2. **Review global state usage**:
   - ASN_CACHE and RDNS_CACHE are global
   - Multiple tests clear and use these caches
   - May need mutex protection or test serialization

3. **Analyze test timeouts**:
   - Add timeout annotations to async tests
   - Check for tests that might wait indefinitely

4. **Memory profiling**:
   - Run tests under valgrind or instruments
   - Check for memory leaks causing SIGKILL

5. **Pre-push hook investigation**:
   - Modify hook to capture detailed output
   - Add timeout to the cargo test command in hook
   - Consider running with RUST_TEST_THREADS=2

## Temporary Workarounds

For CI/CD and development:
```bash
# Run tests with limited parallelism
RUST_TEST_THREADS=2 cargo test

# Or run test suites separately
cargo test --lib
cargo test --bins  
cargo test --tests
cargo test --doc
```

## Files to Review

1. `/Users/dew/dev/nwx/ftr/.git/hooks/pre-push` - The pre-push hook
2. `/Users/dew/dev/nwx/ftr/tests/caching_verification_test.rs` - SIGKILL issue
3. `/Users/dew/dev/nwx/ftr/src/asn/cache.rs` - Global cache
4. `/Users/dew/dev/nwx/ftr/src/dns/cache.rs` - Global cache

## Next Steps

1. Add `#[serial]` test attribute for tests that use global state
2. Add timeouts to all async tests
3. Fix the pre-push hook to use RUST_TEST_THREADS=2
4. Consider using test-specific ports for socket tests
5. Add better error reporting to the pre-push hook