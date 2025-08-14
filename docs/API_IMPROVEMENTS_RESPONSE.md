# API Improvements Response to Critique

This document summarizes the improvements made in response to the API ergonomics critique, and identifies remaining work.

## Completed Improvements ✅

### 1. Fixed Locking Model (Critical)
**Issue**: `Arc<RwLock<Service>>` creates unnecessary double locking since services are already thread-safe internally.

**Solution**: 
- Changed `Services` to use `Arc<Service>` directly
- Removed all `.read().await` calls from the API
- Services are now directly accessible without locking

**Before:**
```rust
let asn_service = ftr.services.asn.read().await;
let result = asn_service.lookup(ip).await;
```

**After:**
```rust
let result = ftr.services.asn.lookup(ip).await;
```

### 2. IPv6 Future-Proofing (Important)
**Issue**: Using `Ipv4Addr` limits the API to IPv4 only.

**Solution**:
- Changed `AsnLookup::lookup()` to accept `IpAddr` instead of `Ipv4Addr`
- Updated `Ftr::lookup_asn()` to accept `IpAddr`
- Added proper error handling for IPv6 (returns error until implemented)
- Added `lookup_ipv4()` convenience method for direct IPv4 usage

**Before:**
```rust
pub async fn lookup_asn(&self, ip: Ipv4Addr) -> Result<AsnInfo>
```

**After:**
```rust
pub async fn lookup_asn(&self, ip: IpAddr) -> Result<AsnInfo>
```

## Remaining Gaps from Critique

### High Priority
1. **Services Visibility**: Services fields are still public. Should be private with accessor methods.
2. **Builder Pattern**: Need `FtrBuilder` and `ServicesBuilder` for better construction ergonomics.
3. **Internal Locking**: Still using `tokio::sync::RwLock` internally. Should switch to `parking_lot::RwLock` or `DashMap`.
4. **RDNS TTL**: Fixed TTL caching is incorrect. Should respect DNS TTLs and implement negative caching (RFC 2308).

### Medium Priority
5. **Batch Operations**: Add `lookup_batch(&[IpAddr])` methods for better throughput.
6. **Streaming API**: Add `trace_stream()` returning `impl Stream<Item = ProbeEvent>`.
7. **Dependency Injection**: Add traits (`DnsResolver`, `StunProvider`) for better testability.
8. **Bounded Concurrency**: Use `Semaphore` to cap enrichment concurrency.

### Nice to Have
9. **Prelude Module**: Create `ftr::prelude` for common imports.
10. **Global Helper**: Optional `ftr::global()` for quick scripts.
11. **Metrics**: Add `tracing` spans and optional metrics.
12. **Cache Persistence**: Load/save cache snapshots for long-running daemons.

## Performance Impact

The locking fix should significantly improve performance:
- **Before**: Double locking overhead (outer `RwLock` + inner locks)
- **After**: Single internal lock only when accessing cache
- **Contention**: Reduced lock contention in concurrent scenarios

## Migration Impact

The changes are mostly backward compatible:
- Services can still be accessed directly via `ftr.services`
- Old cache-based functions still work (deprecated)
- IPv4-specific code needs minor updates to use `IpAddr`

## Code Quality Improvements

1. **Cleaner API**: No more `.read().await` boilerplate
2. **Type Safety**: Using `IpAddr` prepares for IPv6 support
3. **Simpler Mental Model**: Services are just Arc-wrapped objects
4. **Better Examples**: Updated to show the cleaner API

## Next Steps

Priority order for remaining work:

1. **Make Services fields private** - Breaking change but improves encapsulation
2. **Add FtrBuilder** - Non-breaking, improves construction ergonomics
3. **Switch to parking_lot** - Internal change, performance improvement
4. **Implement proper RDNS TTL** - Correctness fix
5. **Add batch methods** - Performance enhancement
6. **Add streaming API** - New feature for better UX

## Conclusion

The critique provided valuable insights that led to immediate improvements in the most critical areas:
- Eliminated unnecessary locking complexity
- Future-proofed the API for IPv6
- Maintained backward compatibility where possible

The remaining items from the critique represent a solid roadmap for continued API improvements, with clear priorities based on impact and complexity.