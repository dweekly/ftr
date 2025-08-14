# Migration Guide: v0.5 to v0.6

## Overview

Version 0.6 introduces a new service-oriented API that replaces the cache-centric approach of v0.5. The new API is cleaner, more intuitive, and hides implementation details like caching behind service abstractions.

## Key Changes

### 1. Service-Oriented Architecture

**Old (v0.5)**: Functions that explicitly mention caches
```rust
use ftr::asn::lookup_asn_with_cache;
use ftr::dns::reverse_dns_lookup_with_cache;

let asn_cache = Arc::new(RwLock::new(AsnCache::new()));
let rdns_cache = Arc::new(RwLock::new(RdnsCache::with_default_ttl()));

let asn_info = lookup_asn_with_cache(ip, &asn_cache, None).await?;
let hostname = reverse_dns_lookup_with_cache(ip, &rdns_cache, None).await?;
```

**New (v0.6)**: Clean service methods
```rust
let ftr = Ftr::new();

let asn_info = ftr.lookup_asn(ip).await?;
let hostname = ftr.lookup_rdns(ip).await?;
```

### 2. Ftr Instance Methods

The `Ftr` struct now provides convenient methods for common operations:

- `lookup_asn(ip)` - Look up ASN information for an IPv4 address
- `lookup_rdns(ip)` - Perform reverse DNS lookup
- `get_public_ip()` - Detect public IP using STUN
- `clear_all_caches()` - Clear all service caches

### 3. Direct Service Access

For advanced use cases, you can access services directly:

```rust
let ftr = Ftr::new();

// Access the ASN service directly
let asn_service = ftr.services.asn.read().await;
let info = asn_service.lookup(ip).await?;

// Check cache statistics
let stats = asn_service.cache_stats().await;
println!("Cache has {} entries", stats.entries);
```

## Migration Steps

### Step 1: Update Imports

**Remove:**
```rust
use ftr::asn::{lookup_asn_with_cache, AsnCache};
use ftr::dns::{reverse_dns_lookup_with_cache, RdnsCache};
use std::sync::Arc;
use tokio::sync::RwLock;
```

**Add:**
```rust
use ftr::Ftr;
```

### Step 2: Replace Cache Creation

**Remove:**
```rust
let asn_cache = Arc::new(RwLock::new(AsnCache::new()));
let rdns_cache = Arc::new(RwLock::new(RdnsCache::with_default_ttl()));
```

**Add:**
```rust
let ftr = Ftr::new();
```

### Step 3: Update Function Calls

**ASN Lookups:**
```rust
// Old
let info = lookup_asn_with_cache(ip, &asn_cache, None).await?;

// New
let info = ftr.lookup_asn(ip).await?;
```

**Reverse DNS:**
```rust
// Old
let hostname = reverse_dns_lookup_with_cache(ip, &rdns_cache, None).await?;

// New
let hostname = ftr.lookup_rdns(ip).await?;
```

### Step 4: Update Traceroute Usage

The traceroute API remains largely the same:

```rust
let ftr = Ftr::new();
let result = ftr.trace("google.com").await?;

// Or with custom config
let config = TracerouteConfig::builder()
    .target("1.1.1.1")
    .max_hops(20)
    .build()?;
let result = ftr.trace_with_config(config).await?;
```

## Advanced Migration

### Custom Service Configuration

If you need custom TTLs or resolvers:

```rust
use ftr::services::Services;
use ftr::dns::service::RdnsLookup;
use std::time::Duration;

// Create custom services
let rdns = RdnsLookup::with_ttl(Duration::from_secs(300));
let services = Services::with_services(None, Some(rdns), None);

// Use custom services in Ftr
// Note: This requires additional API that may be added in future versions
```

### Cache Management

**Old:**
```rust
// Clear individual caches
asn_cache.write().unwrap().clear();
rdns_cache.write().unwrap().clear();
```

**New:**
```rust
// Clear all caches at once
ftr.clear_all_caches().await;

// Or clear individual service caches
let asn_service = ftr.services.asn.write().await;
asn_service.clear_cache().await;
```

## Backward Compatibility

The old cache-based functions (`lookup_asn_with_cache`, `reverse_dns_lookup_with_cache`) are still available but deprecated. They will be removed in v0.7.0.

## Performance Considerations

The new API has the same performance characteristics as v0.5:
- Caching is still performed internally
- Parallel operations are still supported
- No additional overhead from the service abstraction

## Examples

See the `examples/service_api.rs` file for a complete example of the new API.

## Benefits of Migration

1. **Cleaner API**: No need to manage Arc<RwLock> manually
2. **Better Encapsulation**: Caching is an implementation detail
3. **Easier Testing**: Services can be mocked more easily
4. **Future-Proof**: The service API allows for future enhancements without breaking changes

## Getting Help

If you encounter issues during migration:
1. Check the examples in the `examples/` directory
2. Refer to the API documentation
3. Open an issue on GitHub

## Timeline

- **v0.6.0** (Current): New service API introduced, old API deprecated
- **v0.7.0** (Future): Old cache-based API removed