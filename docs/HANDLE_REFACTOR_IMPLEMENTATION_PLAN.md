# Handle Pattern Refactor Implementation Plan for v0.5.0

## Overview
This document provides a detailed, sequenced implementation plan for refactoring ftr from global static caches to an instance-based handle pattern. This is a breaking change targeted for v0.5.0.

## Design Principles
1. **Incremental Testing**: Each phase should be independently testable
2. **Parallel Development**: Keep both patterns working until final cutover
3. **Type Safety**: Use Rust's type system to prevent misuse
4. **Thread Safety**: Ensure caches remain thread-safe with Arc<RwLock<>>
5. **Zero Cost**: No performance regression from the refactor

## Detailed Implementation Phases

### Phase 1: Create Ftr Struct and Cache Infrastructure
**Goal**: Establish the new ownership model without breaking existing code

#### Step 1.1: Define Cache Wrapper Types
Create `src/caches.rs`:
```rust
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct Caches {
    pub asn: Arc<RwLock<crate::asn::cache::AsnCache>>,
    pub rdns: Arc<RwLock<crate::dns::cache::RdnsCache>>,
    pub stun: Arc<RwLock<crate::public_ip::stun_cache::StunCache>>,
}

impl Caches {
    pub fn new() -> Self {
        Self {
            asn: Arc::new(RwLock::new(crate::asn::cache::AsnCache::new())),
            rdns: Arc::new(RwLock::new(crate::dns::cache::RdnsCache::new())),
            stun: Arc::new(RwLock::new(crate::public_ip::stun_cache::StunCache::new())),
        }
    }
}
```

#### Step 1.2: Create the Ftr Struct
Update `src/lib.rs`:
```rust
pub struct Ftr {
    caches: Caches,
}

impl Ftr {
    pub fn new() -> Self {
        Self {
            caches: Caches::new(),
        }
    }
    
    pub fn with_caches(caches: Caches) -> Self {
        Self { caches }
    }
}
```

#### Step 1.3: Add Instance Methods (Parallel to Existing)
```rust
impl Ftr {
    pub async fn trace(&self, target: &str) -> Result<TracerouteResult, TracerouteError> {
        let config = TracerouteConfig::builder()
            .target(target)
            .build()?;
        self.trace_with_config(config).await
    }
    
    pub async fn trace_with_config(&self, config: TracerouteConfig) 
        -> Result<TracerouteResult, TracerouteError> {
        // Will call new internal functions with caches
        traceroute::async_api::trace_with_caches(config, &self.caches).await
    }
}
```

**Testing**: Create `tests/handle_pattern_test.rs` to test new API alongside old

### Phase 2: Thread Caches Through Async Engine
**Goal**: Enable the async engine to use injected caches

#### Step 2.1: Create Parallel Functions with Cache Parameters
In `src/traceroute/async_api.rs`:
```rust
pub(crate) async fn trace_with_caches(
    config: TracerouteConfig,
    caches: &Caches,
) -> Result<TracerouteResult, TracerouteError> {
    let traceroute = AsyncTraceroute::new_with_caches(config, caches).await?;
    traceroute.run().await
}
```

#### Step 2.2: Update AsyncTraceroute
```rust
pub struct AsyncTraceroute {
    config: TracerouteConfig,
    caches: Option<Caches>, // Optional to maintain compatibility
}

impl AsyncTraceroute {
    pub async fn new_with_caches(config: TracerouteConfig, caches: &Caches) 
        -> Result<Self, TracerouteError> {
        // Implementation with injected caches
    }
    
    // Keep existing new() for compatibility
    pub async fn new(config: TracerouteConfig) -> Result<Self, TracerouteError> {
        // Uses global caches
    }
}
```

#### Step 2.3: Update FullyParallelAsyncEngine
```rust
pub struct FullyParallelAsyncEngine {
    // ... existing fields ...
    caches: Option<Caches>,
}
```

**Testing**: Test both paths work correctly

### Phase 3: Update Enrichment Functions
**Goal**: Allow enrichment functions to use injected caches

#### Step 3.1: Create Cache-Aware Versions
In `src/asn/lookup.rs`:
```rust
pub async fn lookup_asn_with_cache(
    ip: Ipv4Addr,
    cache: &Arc<RwLock<AsnCache>>,
) -> Option<AsnInfo> {
    // Check cache first
    let cache_read = cache.read().await;
    if let Some(info) = cache_read.get(&ip) {
        return Some(info.clone());
    }
    drop(cache_read);
    
    // Lookup and update cache
    let info = lookup_asn_uncached(ip).await?;
    let mut cache_write = cache.write().await;
    cache_write.insert(ip, info.clone());
    Some(info)
}

// Keep existing for compatibility
pub async fn lookup_asn(ip: Ipv4Addr) -> Option<AsnInfo> {
    lookup_asn_with_cache(ip, &ASN_CACHE).await
}
```

#### Step 3.2: Update DNS Functions
Similar pattern for `src/dns/reverse.rs`

#### Step 3.3: Update STUN Functions
Similar pattern for `src/public_ip/stun.rs`

**Testing**: Unit tests for cache-aware functions

### Phase 4: Update ISP Detection
**Goal**: Thread caches through ISP detection logic

#### Step 4.1: Update detect_isp Functions
In `src/public_ip/mod.rs`:
```rust
pub async fn detect_isp_with_caches(
    caches: &Caches,
) -> Result<IspInfo, String> {
    // Implementation using injected caches
}
```

#### Step 4.2: Update Path Classification
In `src/traceroute/isp_from_path.rs`:
```rust
pub fn classify_hops_with_caches(
    hops: &[RawHopInfo],
    isp_info: Option<&IspInfo>,
    caches: &Caches,
) -> Vec<ClassifiedHopInfo> {
    // Implementation using injected caches
}
```

**Testing**: Integration tests for ISP detection

### Phase 5: Remove Global Caches
**Goal**: Complete the migration

#### Step 5.1: Update All Call Sites
- Remove all references to global caches
- Update all functions to use cache parameters
- Remove compatibility functions

#### Step 5.2: Delete Global Cache Declarations
- Remove `pub static ASN_CACHE` from `src/asn/cache.rs`
- Remove `pub static RDNS_CACHE` from `src/dns/cache.rs`
- Remove `pub static STUN_CACHE` from `src/public_ip/stun_cache.rs`

#### Step 5.3: Remove Old API Functions
- Remove free functions `trace` and `trace_with_config`
- Update module exports

**Testing**: Full test suite should pass

### Phase 6: Update CLI
**Goal**: Update main.rs to use Ftr instance

```rust
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let ftr = Ftr::new();
    
    let result = ftr.trace_with_config(config).await?;
    // ... rest of CLI logic
}
```

### Phase 7: Update All Tests
**Goal**: Migrate tests to new API

- Update unit tests in each module
- Update integration tests
- Remove serial test attributes
- Verify tests run in parallel successfully

### Phase 8: Update Examples
**Goal**: Show users how to use new API

Update all examples in `examples/` directory

### Phase 9: Documentation and Version
**Goal**: Prepare for release

- Update README.md with new API examples
- Update library documentation
- Bump version to 0.5.0 in Cargo.toml
- Update CHANGELOG.md

### Phase 10: Final Testing and Validation
**Goal**: Ensure quality

- Run full test suite with `--test-threads=1` and default
- Run benchmarks to verify no performance regression
- Test on all supported platforms
- Run examples to verify they work

## Migration Guide for Users

### Before (v0.4.x)
```rust
use ftr::{trace, trace_with_config};

let result = trace("google.com").await?;
```

### After (v0.5.0)
```rust
use ftr::Ftr;

let ftr = Ftr::new();
let result = ftr.trace("google.com").await?;
```

### Advanced Usage
```rust
// Share caches across multiple operations
let ftr = Ftr::new();
let results = futures::future::join_all(
    targets.iter().map(|target| ftr.trace(target))
).await;

// Custom cache configuration
let caches = Caches::new();
// Optionally pre-populate caches
let ftr = Ftr::with_caches(caches);
```

## Testing Strategy

### Unit Tests
- Each module gets cache-aware test variants
- Test cache isolation between Ftr instances
- Test concurrent access to shared caches

### Integration Tests
```rust
#[tokio::test]
async fn test_multiple_instances_isolated() {
    let ftr1 = Ftr::new();
    let ftr2 = Ftr::new();
    
    // Operations on ftr1 don't affect ftr2's caches
    let result1 = ftr1.trace("8.8.8.8").await.unwrap();
    let result2 = ftr2.trace("8.8.8.8").await.unwrap();
    
    // Each instance has independent cache state
}
```

### Performance Tests
- Benchmark cache-aware vs global cache performance
- Verify no regression in trace operations
- Test memory usage with multiple instances

## Risk Mitigation

1. **Incremental Rollout**: Keep both APIs working until confident
2. **Feature Flag**: Consider `legacy-api` feature flag for transition
3. **Performance Monitoring**: Benchmark at each phase
4. **Rollback Plan**: Git tags at each phase for easy rollback

## Success Criteria

- [ ] All tests pass without `#[serial]` attributes
- [ ] No performance regression (within 5%)
- [ ] Multiple Ftr instances work independently
- [ ] Clean API without global state
- [ ] Documentation updated and clear
- [ ] Examples demonstrate best practices