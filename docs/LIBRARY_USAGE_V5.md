# Using ftr as a Library (v0.5.0)

This guide covers how to use ftr v0.5.0 as a Rust library in your own applications.

## Breaking Changes in v0.5.0

Version 0.5.0 introduces a handle-based API that eliminates global state:

- **NEW**: `Ftr` struct that owns all caches and state
- **REMOVED**: Global functions `trace()` and `trace_with_config()`
- **REMOVED**: Direct access to global caches (ASN_CACHE, RDNS_CACHE, STUN_CACHE)
- **BENEFIT**: Thread-safe, allows multiple isolated instances
- **BENEFIT**: Better testability and resource management

## Installation

Add ftr to your `Cargo.toml`:

```toml
[dependencies]
ftr = "0.5.0"
tokio = { version = "1", features = ["full"] }
```

## Quick Start

```rust
use ftr::{Ftr, TracerouteResult};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create an Ftr instance
    let ftr = Ftr::new();
    
    // Simple trace with defaults
    let result = ftr.trace("google.com").await?;
    
    // Print results
    for hop in &result.hops {
        if let Some(addr) = hop.addr {
            println!("Hop {}: {} ({:?}ms)", hop.ttl, addr, hop.rtt_ms());
        }
    }
    
    Ok(())
}
```

## The Ftr Handle

The `Ftr` struct is the main entry point for the library:

```rust
use ftr::Ftr;

// Create with fresh caches
let ftr = Ftr::new();

// Or use Default trait
let ftr = Ftr::default();
```

### Custom Caches

You can provide your own pre-initialized caches:

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

## Configuration

Use `TracerouteConfigBuilder` for fine-grained control:

```rust
use ftr::{Ftr, TracerouteConfigBuilder};
use std::time::Duration;

let ftr = Ftr::new();

let config = TracerouteConfigBuilder::new()
    .target("1.1.1.1")
    .max_hops(20)
    .start_ttl(1)
    .probe_timeout(Duration::from_millis(500))
    .queries_per_hop(3)
    .enable_asn_lookup(true)
    .enable_rdns(true)
    .port(443)  // For UDP/TCP modes
    .build()?;

let result = ftr.trace_with_config(config).await?;
```

## Multiple Instances

Unlike previous versions, v0.5.0 allows multiple isolated Ftr instances:

```rust
use ftr::Ftr;
use tokio::task;

// Each instance has its own caches
let ftr1 = Ftr::new();
let ftr2 = Ftr::new();

// Run traces concurrently with isolated caches
let handle1 = task::spawn(async move {
    ftr1.trace("google.com").await
});

let handle2 = task::spawn(async move {
    ftr2.trace("cloudflare.com").await
});

let result1 = handle1.await??;
let result2 = handle2.await??;
```

## Working with Results

The `TracerouteResult` structure remains unchanged:

```rust
use ftr::{Ftr, TracerouteResult, SegmentType};

async fn analyze_trace(ftr: &Ftr, target: &str) -> Result<(), Box<dyn std::error::Error>> {
    let result = ftr.trace(target).await?;
    
    println!("Target: {} ({})", result.target, result.target_ip);
    println!("Reached: {}", result.destination_reached);
    
    // Analyze network segments
    for hop in &result.hops {
        match hop.segment {
            SegmentType::Lan => println!("LAN hop: {:?}", hop.addr),
            SegmentType::Isp => println!("ISP hop: {:?}", hop.addr),
            SegmentType::Beyond => println!("External hop: {:?}", hop.addr),
            _ => {}
        }
        
        // ASN information
        if let Some(asn_info) = &hop.asn_info {
            println!("  AS{}: {} ({})", 
                asn_info.asn, 
                asn_info.name, 
                asn_info.country_code
            );
        }
        
        // Reverse DNS
        if let Some(hostname) = &hop.hostname {
            println!("  Hostname: {}", hostname);
        }
    }
    
    // ISP detection
    if let Some(isp) = &result.isp_info {
        println!("Your ISP: {} (AS{})", isp.name, isp.asn);
        println!("Public IP: {}", isp.public_ip);
    }
    
    Ok(())
}
```

## Performance Optimization

The new handle-based API provides better cache management:

```rust
use ftr::Ftr;
use std::net::IpAddr;

// Create a single Ftr instance for your application
let ftr = Ftr::new();

// Reuse the same instance for multiple traces
// Caches are automatically shared across all traces
for target in ["google.com", "cloudflare.com", "amazon.com"] {
    let result = ftr.trace(target).await?;
    println!("{}: {} hops", target, result.hop_count());
}

// Pre-populate public IP cache
let config = TracerouteConfigBuilder::new()
    .target("1.1.1.1")
    .public_ip("203.0.113.1".parse()?)  // Skip STUN detection
    .build()?;
let result = ftr.trace_with_config(config).await?;
```

## Migration from v0.4.x

### Old API (v0.4.x and earlier):
```rust
// Global functions
let result = ftr::trace("google.com").await?;
let result = ftr::trace_with_config(config).await?;
```

### New API (v0.5.0):
```rust
// Instance methods
let ftr = Ftr::new();
let result = ftr.trace("google.com").await?;
let result = ftr.trace_with_config(config).await?;
```

### Cache Access

Direct cache access is no longer available. All caching is handled internally by the Ftr instance.

## Error Handling

Error handling remains the same with structured errors:

```rust
use ftr::{Ftr, TracerouteError};

let ftr = Ftr::new();

match ftr.trace("example.com").await {
    Ok(result) => {
        println!("Success: {} hops", result.hop_count());
    }
    Err(TracerouteError::InsufficientPermissions { required, suggestion }) => {
        eprintln!("Permission error: {}", required);
        eprintln!("Suggestion: {}", suggestion);
    }
    Err(TracerouteError::Ipv6NotSupported) => {
        eprintln!("IPv6 is not yet supported");
    }
    Err(e) => {
        eprintln!("Error: {}", e);
    }
}
```

## Thread Safety

The Ftr struct is thread-safe and can be shared across threads:

```rust
use std::sync::Arc;
use ftr::Ftr;
use tokio::task;

let ftr = Arc::new(Ftr::new());

let mut handles = vec![];
for i in 0..10 {
    let ftr_clone = Arc::clone(&ftr);
    let handle = task::spawn(async move {
        ftr_clone.trace(&format!("target{}.com", i)).await
    });
    handles.push(handle);
}

for handle in handles {
    let result = handle.await??;
    // Process result
}
```

## Platform Support

v0.5.0 maintains support for all platforms:

- **Linux**: Async UDP with IP_RECVERR and async raw ICMP
- **macOS**: Async DGRAM ICMP 
- **Windows**: Async Windows ICMP API (IcmpSendEcho2)
- **FreeBSD/OpenBSD**: Async raw ICMP

## Examples

See the `examples/` directory for complete examples:

- `simple_trace.rs` - Basic usage
- `error_handling.rs` - Comprehensive error handling
- `parallel_traces.rs` - Running multiple traces
- `custom_socket.rs` - Custom socket configuration

## Support

For issues or questions, please visit: https://github.com/dweekly/ftr