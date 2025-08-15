# feat: v0.5.0 - Service-Oriented API with Complete Handle Pattern Implementation

## Summary

This PR introduces **ftr v0.5.0**, a major release that completely redesigns the library API from a cache-centric to a **service-oriented architecture**. The new design eliminates all global state, introduces the `Ftr` handle pattern for instance-based usage, and provides a clean, intuitive API that focuses on what services do rather than implementation details.

## Key Improvements

### 🏗️ Service-Oriented Architecture
- **New `Ftr` struct** as the main library handle
- **Service container pattern** with direct access to ASN, DNS, and STUN services
- **No more `Arc<RwLock>`** - services handle their own thread safety internally
- **Convenience methods** for common operations (`lookup_asn()`, `lookup_rdns()`, `get_public_ip()`)

### 🚀 Future-Proof API Design
- **IPv6 ready** - All APIs now accept `IpAddr` instead of `Ipv4Addr`
- **Graceful IPv6 handling** - Returns appropriate errors until full IPv6 support
- **Clean service boundaries** - Each service manages its own cache and lifecycle

### 🧪 True Parallel Testing
- **200+ tests** run fully in parallel (767% CPU utilization)
- **Complete cache isolation** between instances
- **No more `#[serial]` tests** - removed `serial_test` dependency
- **36.8s total test time** for comprehensive test suite

### 📚 Developer Experience
- **Intuitive API** - `ftr.lookup_asn(ip)` instead of cache-based functions
- **Clear migration path** with comprehensive documentation
- **New examples** demonstrating service-oriented patterns
- **Better error messages** and structured error types

## Breaking Changes

### API Changes
```rust
// Old (v0.4.x)
let result = ftr::trace("google.com").await?;

// New (v0.5.0)
let ftr = Ftr::new();
let result = ftr.trace("google.com").await?;
```

### Service Access
```rust
// New service methods (clean, intuitive)
let asn_info = ftr.lookup_asn(ip).await?;
let hostname = ftr.lookup_rdns(ip).await?;

// Or direct service access (no locking needed!)
let asn_info = ftr.services.asn.lookup(ip).await?;
```

### Removed APIs
- Global `trace()` and `trace_with_config()` functions
- Global static caches (`ASN_CACHE`, `RDNS_CACHE`, `STUN_CACHE`)
- Cache-based functions (`lookup_asn_with_cache`, `reverse_dns_lookup_with_cache`)
- Backward compatibility type aliases
- Global timing configuration overrides

## Implementation Details

### Architecture Changes
1. **Phase 1**: Created `Ftr` struct and `Caches` container
2. **Phase 2**: Migrated all functions to instance methods
3. **Phase 3**: Introduced `Services` container with service-oriented API
4. **Phase 4**: Removed all deprecated functions and backward compatibility

### Performance Improvements
- Simplified locking model (removed unnecessary Arc<RwLock> wrapper)
- Better cache locality with instance-based design
- True parallel test execution without lock contention
- Faster service access without multiple lock acquisitions

## Migration Guide

See [CHANGELOG.md](CHANGELOG.md#migration-guide) for detailed migration instructions.

## Testing

- ✅ All 200+ tests passing
- ✅ CI/CD pipeline green on all platforms (Linux, macOS, Windows, FreeBSD, OpenBSD)
- ✅ Documentation builds without warnings
- ✅ No clippy warnings
- ✅ Security audit passed

## Related Issues

Closes #[issue-number] - Implement handle pattern for v0.5.0

## Checklist

- [x] Code compiles without warnings
- [x] All tests pass
- [x] Documentation updated
- [x] CHANGELOG.md updated
- [x] Breaking changes documented
- [x] Migration guide provided
- [x] Examples updated
- [x] CI/CD passes on all platforms