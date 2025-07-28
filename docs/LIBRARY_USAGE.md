# Using ftr as a Library

This guide covers how to use ftr as a Rust library in your own applications.

## Installation

Add ftr to your `Cargo.toml`:

```toml
[dependencies]
ftr = "0.3"
tokio = { version = "1", features = ["full"] }
```

## Quick Start

```rust
use ftr::{trace, TracerouteResult};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Simple trace with defaults
    let result = trace("google.com").await?;
    
    // Print results
    for hop in &result.hops {
        if let Some(addr) = hop.addr {
            println!("Hop {}: {} ({:?}ms)", hop.ttl, addr, hop.rtt_ms());
        }
    }
    
    Ok(())
}
```

## Configuration

Use `TracerouteConfigBuilder` for fine-grained control:

```rust
use ftr::{TracerouteConfigBuilder, trace_with_config};
use std::time::Duration;

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

let result = trace_with_config(config).await?;
```

## Working with Results

The `TracerouteResult` provides rich information about each hop:

```rust
use ftr::{TracerouteResult, SegmentType};

fn analyze_results(result: &TracerouteResult) {
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
}
```

## Performance Optimization

For applications performing multiple traces, ftr provides caching:

```rust
use ftr::{TracerouteConfigBuilder, trace_with_config};
use std::net::IpAddr;

// Detect public IP once
let detect_config = TracerouteConfigBuilder::new()
    .target("1.1.1.1")
    .max_hops(1)
    .build()?;

let detect_result = trace_with_config(detect_config).await?;
let my_public_ip = detect_result.isp_info.map(|isp| isp.public_ip);

// Reuse for subsequent traces
for target in ["google.com", "cloudflare.com", "github.com"] {
    let mut builder = TracerouteConfigBuilder::new()
        .target(target)
        .enable_asn_lookup(true)
        .enable_rdns(true);
    
    // Provide public IP to skip detection
    if let Some(ip) = my_public_ip {
        builder = builder.public_ip(ip);
    }
    
    let config = builder.build()?;
    let result = trace_with_config(config).await?;
    // Process result...
}
```

## Protocol and Socket Modes

ftr supports different protocols and socket modes:

```rust
use ftr::{ProbeProtocol, SocketMode};

// ICMP with raw sockets (default, requires privileges)
let config = TracerouteConfigBuilder::new()
    .target("example.com")
    .protocol(ProbeProtocol::Icmp)
    .socket_mode(SocketMode::Raw)
    .build()?;

// UDP probes (may not require privileges)
let config = TracerouteConfigBuilder::new()
    .target("example.com")
    .protocol(ProbeProtocol::Udp)
    .port(33434)  // Starting UDP port
    .build()?;
```

## Error Handling

```rust
use ftr::{TracerouteError, trace};

match trace("example.com").await {
    Ok(result) => {
        // Process successful result
    }
    Err(TracerouteError::SocketError(e)) => {
        eprintln!("Socket error (may need privileges): {}", e);
    }
    Err(TracerouteError::ResolutionError(e)) => {
        eprintln!("DNS resolution failed: {}", e);
    }
    Err(e) => {
        eprintln!("Traceroute failed: {}", e);
    }
}
```

## Platform Considerations

### Privileges

- **Linux/macOS**: Raw ICMP sockets require root or appropriate capabilities
- **Windows**: No special privileges needed (uses Windows ICMP API)
- **FreeBSD/OpenBSD**: Requires root or setuid

### Fallback Strategies

```rust
use ftr::{TracerouteConfigBuilder, ProbeProtocol};

// Try ICMP first, fall back to UDP if needed
let result = match trace("example.com").await {
    Ok(res) => res,
    Err(_) => {
        // Try UDP if ICMP fails
        let config = TracerouteConfigBuilder::new()
            .target("example.com")
            .protocol(ProbeProtocol::Udp)
            .build()?;
        trace_with_config(config).await?
    }
};
```

## Advanced Features

### Custom Resolvers

```rust
use ftr::dns::create_default_resolver;
use std::sync::Arc;

let resolver = Arc::new(create_default_resolver());
// Use resolver for DNS operations...
```

### Cache Management

```rust
// Check cache statistics
println!("ASN cache size: {}", ftr::asn::ASN_CACHE.len());
println!("rDNS cache size: {}", ftr::dns::RDNS_CACHE.len());

// Clear caches if needed
ftr::asn::ASN_CACHE.clear();
ftr::dns::RDNS_CACHE.clear();
```

### Streaming Progress

```rust
use ftr::Traceroute;

let mut traceroute = Traceroute::new("example.com")?;

// Configure as needed
traceroute.set_max_hops(30);

// Get progress updates (in a real app, this would be in a separate task)
let progress = traceroute.get_progress();
println!("Progress: {}%", progress.percentage());
```

## Complete Example

```rust
use ftr::{TracerouteConfigBuilder, trace_with_config};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Configure traceroute
    let config = TracerouteConfigBuilder::new()
        .target("dns.google")
        .max_hops(30)
        .probe_timeout(Duration::from_millis(1000))
        .queries_per_hop(3)
        .enable_asn_lookup(true)
        .enable_rdns(true)
        .verbose(true)
        .build()?;
    
    // Run traceroute
    println!("Tracing route to {}...", config.target);
    let result = trace_with_config(config).await?;
    
    // Display results
    println!("\nTraceroute completed in {:?}", result.total_duration);
    println!("Destination reached: {}", result.destination_reached);
    
    for hop in &result.hops {
        if let Some(addr) = hop.addr {
            print!("{:2}. {} ", hop.ttl, addr);
            
            if let Some(hostname) = &hop.hostname {
                print!("({}) ", hostname);
            }
            
            if let Some(rtt) = hop.rtt_ms() {
                print!("{:.2}ms ", rtt);
            }
            
            if let Some(asn) = &hop.asn_info {
                print!("[AS{} - {}] ", asn.asn, asn.name);
            }
            
            println!();
        } else {
            println!("{:2}. * * *", hop.ttl);
        }
    }
    
    if let Some(isp) = &result.isp_info {
        println!("\nYour ISP: {} (AS{})", isp.name, isp.asn);
        println!("Public IP: {}", isp.public_ip);
    }
    
    Ok(())
}
```

## API Documentation

For detailed API documentation, run:

```bash
cargo doc --open
```

## License

ftr is available under the MIT license. See LICENSE file for details.