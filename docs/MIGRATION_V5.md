# Migration Guide: v0.4.x to v0.5.0

## Overview

Version 0.5.0 introduces a handle-based API that eliminates global state. This is a breaking change that requires updating your code, but the migration is straightforward.

## Key Changes

1. **No more global functions** - `ftr::trace()` and `ftr::trace_with_config()` are removed
2. **Introduce Ftr handle** - All functionality is now accessed through an `Ftr` instance
3. **Isolated caches** - Each `Ftr` instance has its own caches
4. **Better concurrency** - Multiple instances can run independently

## Simple Migration

### Basic Usage

**Before (v0.4.x):**
```rust
use ftr::trace;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let result = trace("google.com").await?;
    println!("Found {} hops", result.hop_count());
    Ok(())
}
```

**After (v0.5.0):**
```rust
use ftr::Ftr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let ftr = Ftr::new();
    let result = ftr.trace("google.com").await?;
    println!("Found {} hops", result.hop_count());
    Ok(())
}
```

### With Configuration

**Before (v0.4.x):**
```rust
use ftr::{trace_with_config, TracerouteConfigBuilder};

let config = TracerouteConfigBuilder::new()
    .target("1.1.1.1")
    .max_hops(20)
    .build()?;
let result = trace_with_config(config).await?;
```

**After (v0.5.0):**
```rust
use ftr::{Ftr, TracerouteConfigBuilder};

let ftr = Ftr::new();
let config = TracerouteConfigBuilder::new()
    .target("1.1.1.1")
    .max_hops(20)
    .build()?;
let result = ftr.trace_with_config(config).await?;
```

## Advanced Usage

### Sharing Ftr Across Functions

**Before (v0.4.x):**
```rust
async fn trace_target(target: &str) -> Result<TracerouteResult, Box<dyn Error>> {
    ftr::trace(target).await
}

async fn main() {
    let result = trace_target("google.com").await?;
}
```

**After (v0.5.0):**
```rust
async fn trace_target(ftr: &Ftr, target: &str) -> Result<TracerouteResult, Box<dyn Error>> {
    ftr.trace(target).await
}

async fn main() {
    let ftr = Ftr::new();
    let result = trace_target(&ftr, "google.com").await?;
}
```

### Concurrent Traces

**Before (v0.4.x):**
```rust
use tokio::task;

// Global caches were shared automatically
let handle1 = task::spawn(async {
    ftr::trace("google.com").await
});

let handle2 = task::spawn(async {
    ftr::trace("cloudflare.com").await
});
```

**After (v0.5.0) - Shared Instance:**
```rust
use std::sync::Arc;
use tokio::task;

// Share one instance for cache sharing
let ftr = Arc::new(Ftr::new());

let ftr1 = Arc::clone(&ftr);
let handle1 = task::spawn(async move {
    ftr1.trace("google.com").await
});

let ftr2 = Arc::clone(&ftr);
let handle2 = task::spawn(async move {
    ftr2.trace("cloudflare.com").await
});
```

**After (v0.5.0) - Isolated Instances:**
```rust
use tokio::task;

// Create separate instances for isolation
let handle1 = task::spawn(async {
    let ftr = Ftr::new();
    ftr.trace("google.com").await
});

let handle2 = task::spawn(async {
    let ftr = Ftr::new();
    ftr.trace("cloudflare.com").await
});
```

## Struct/Application Integration

If you're integrating ftr into a larger application:

**Before (v0.4.x):**
```rust
struct NetworkDiagnostics {
    // Other fields...
}

impl NetworkDiagnostics {
    async fn check_connectivity(&self, target: &str) -> Result<bool, Box<dyn Error>> {
        let result = ftr::trace(target).await?;
        Ok(result.destination_reached)
    }
}
```

**After (v0.5.0):**
```rust
struct NetworkDiagnostics {
    ftr: Ftr,
    // Other fields...
}

impl NetworkDiagnostics {
    fn new() -> Self {
        Self {
            ftr: Ftr::new(),
            // Initialize other fields...
        }
    }

    async fn check_connectivity(&self, target: &str) -> Result<bool, Box<dyn Error>> {
        let result = self.ftr.trace(target).await?;
        Ok(result.destination_reached)
    }
}
```

## Testing

The new API makes testing easier with isolated instances:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use ftr::Ftr;

    #[tokio::test]
    async fn test_trace() {
        // Each test gets its own isolated instance
        let ftr = Ftr::new();
        let result = ftr.trace("127.0.0.1").await.unwrap();
        assert!(result.destination_reached);
    }

    #[tokio::test]
    async fn test_concurrent_traces() {
        // Tests don't interfere with each other
        let ftr1 = Ftr::new();
        let ftr2 = Ftr::new();
        
        let (r1, r2) = tokio::join!(
            ftr1.trace("127.0.0.1"),
            ftr2.trace("127.0.0.1")
        );
        
        assert!(r1.is_ok());
        assert!(r2.is_ok());
    }
}
```

## Custom Caches

If you were manually managing caches:

**Before (v0.4.x):**
```rust
// Global caches were accessed directly (not recommended)
// No official API for this
```

**After (v0.5.0):**
```rust
use ftr::{Ftr, asn::cache::AsnCache, dns::cache::RdnsCache, 
          public_ip::stun_cache::StunCache};

// Create custom caches
let asn_cache = AsnCache::new();
let rdns_cache = RdnsCache::with_default_ttl();
let stun_cache = StunCache::new();

// Create Ftr with custom caches
let ftr = Ftr::with_caches(
    Some(asn_cache),
    Some(rdns_cache),
    Some(stun_cache)
);
```

## Benefits of the New API

1. **Better Testing** - Each test can have isolated caches
2. **Cleaner Code** - No hidden global state
3. **Flexibility** - Choose between shared or isolated instances
4. **Thread Safety** - Built-in safe sharing with Arc
5. **Resource Management** - Caches are cleaned up when Ftr is dropped

## Need Help?

If you encounter any issues during migration:

1. Check the examples in `examples/` directory
2. Review the API documentation: `cargo doc --open`
3. Open an issue: https://github.com/dweekly/ftr/issues