# Timing Configuration System

This document describes the timing configuration system introduced in ftr v0.3.1 to eliminate hardcoded timing values and enable runtime configuration.

## Overview

The timing configuration system provides a centralized way to manage all timing-related parameters in ftr. This addresses the issue of hardcoded delays and polling intervals that were scattered throughout the codebase, making it difficult to optimize performance for different environments.

## Architecture

### 1. TimingConfig Structure

Located in `src/traceroute/config.rs`, the `TimingConfig` structure contains all timing parameters:

```rust
pub struct TimingConfig {
    /// Receiver thread polling interval (default: 100ms)
    pub receiver_poll_interval: Duration,
    
    /// Main wait loop polling interval (default: 10ms)
    pub main_loop_poll_interval: Duration,
    
    /// Enrichment completion wait time (default: 100ms)
    pub enrichment_wait_time: Duration,
    
    /// Socket read timeout (default: 100ms)
    pub socket_read_timeout: Duration,
    
    /// UDP socket retry delay (default: 10ms)
    pub udp_retry_delay: Duration,
}
```

### 2. Global Timing Module

The `src/config/timing.rs` module provides:

- **Compile-time defaults**: Constants defining default values
- **Runtime overrides**: Global configuration that can be set once at startup
- **Accessor functions**: Type-safe access to timing values throughout the codebase

#### Default Values

```rust
pub const DEFAULT_SOCKET_READ_TIMEOUT_MS: u64 = 100;
pub const DEFAULT_UDP_RETRY_DELAY_MS: u64 = 10;
pub const DEFAULT_RECEIVER_POLL_INTERVAL_MS: u64 = 100;
pub const DEFAULT_MAIN_LOOP_POLL_INTERVAL_MS: u64 = 10;
pub const DEFAULT_ENRICHMENT_WAIT_TIME_MS: u64 = 100;
```

#### Usage Example

```rust
use crate::config::timing;

// Get the current socket read timeout
let timeout = timing::socket_read_timeout();

// Set custom configuration at startup
let custom_config = TimingConfig {
    socket_read_timeout: Duration::from_millis(50),
    // ... other fields
};
timing::set_config(custom_config)?;
```

## Integration Points

### Socket Implementations

All socket implementations now use the timing configuration:

- **Windows ICMP** (`windows.rs`, `windows_async.rs`): Uses `socket_read_timeout()`
- **Raw ICMP** (`icmp_v4.rs`): Uses `socket_read_timeout()` for recv operations
- **UDP** (`udp.rs`): Uses `udp_retry_delay()` for retry loops

### Traceroute Engine

The main traceroute engine (`engine.rs`) uses:

- `receiver_poll_interval()` for the receiver thread
- `main_loop_poll_interval()` for the main wait loop
- `enrichment_wait_time()` for enrichment completion

### Async Implementation

The async implementation passes `TimingConfig` directly to async sockets, allowing immediate response processing without polling.

## Benefits

1. **No Hardcoded Values**: All timing values are centralized and configurable
2. **Runtime Configuration**: Timing can be adjusted without recompilation
3. **Performance Optimization**: Different environments can use different timing values
4. **Testability**: Tests can use shorter timeouts for faster execution
5. **Future-Proof**: Easy to add new timing parameters as needed

## Migration Guide

### For Library Users

If you're using ftr as a library and want to customize timing:

```rust
use ftr::{TracerouteConfig, TimingConfig};
use std::time::Duration;

// Create custom timing configuration
let timing = TimingConfig {
    socket_read_timeout: Duration::from_millis(50),
    receiver_poll_interval: Duration::from_millis(50),
    main_loop_poll_interval: Duration::from_millis(5),
    enrichment_wait_time: Duration::from_millis(50),
    udp_retry_delay: Duration::from_millis(5),
};

// Apply to traceroute config
let config = TracerouteConfig::builder()
    .target("example.com")
    .timing_config(timing)
    .build()?;
```

### For Developers

When adding new time-based operations:

1. Add new constants to `src/config/timing.rs`
2. Add corresponding field to `TimingConfig`
3. Create accessor function in timing module
4. Use the accessor instead of hardcoding delays

## Future Improvements

1. **CLI Arguments**: Add command-line flags for common timing adjustments
2. **Environment Variables**: Support timing configuration via environment
3. **Profiles**: Pre-defined timing profiles (fast, normal, reliable)
4. **Auto-Tuning**: Dynamically adjust timing based on network conditions

## Related Work

- **Async Implementation**: The async socket implementation (Windows only) eliminates most timing dependencies by using event-driven I/O
- **IOCP Integration**: Future IOCP support will further reduce timing sensitivity on Windows