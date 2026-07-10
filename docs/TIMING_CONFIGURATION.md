# Timing Configuration System

This document describes how ftr's internal timing parameters are organized
and how library users can tune them.

## Overview

All timing-related parameters live in one place instead of being hardcoded
throughout the codebase. There are two pieces:

1. **`TimingConfig`** (`src/traceroute/config.rs`, re-exported as
   `ftr::TimingConfig`) — the runtime configuration struct, set per-trace via
   `TracerouteConfigBuilder::timing()`.
2. **Default constants** (`src/config/timing.rs`, `ftr::config::timing`) —
   the documented, centralized default values that `TimingConfig::default()`
   uses, plus Windows-specific timeout floors used by the Windows ICMP socket.

## TimingConfig Structure

```rust
pub struct TimingConfig {
    /// Receiver thread polling interval (default: 1ms)
    pub receiver_poll_interval: Duration,

    /// Main wait loop polling interval (default: 5ms)
    pub main_loop_poll_interval: Duration,

    /// Enrichment completion wait time (default: 200ms)
    pub enrichment_wait_time: Duration,

    /// Socket read timeout (default: 50ms)
    pub socket_read_timeout: Duration,

    /// UDP socket retry delay (default: 5ms)
    pub udp_retry_delay: Duration,
}
```

## Default Constants

Defined in `ftr::config::timing`:

```rust
pub const DEFAULT_SOCKET_READ_TIMEOUT_MS: u64 = 50;
pub const DEFAULT_UDP_RETRY_DELAY_MS: u64 = 5;
pub const DEFAULT_RECEIVER_POLL_INTERVAL_MS: u64 = 1;
pub const DEFAULT_MAIN_LOOP_POLL_INTERVAL_MS: u64 = 5;
pub const DEFAULT_ENRICHMENT_WAIT_TIME_MS: u64 = 200;
```

Windows-specific floors (`WINDOWS_MIN_SOCKET_READ_TIMEOUT_MS`,
`WINDOWS_ICMP_MIN_TIMEOUT_MS`, `WINDOWS_ICMP_MIN_TOTAL_TIMEOUT_MS`,
`WINDOWS_ICMP_TIMEOUT_BUFFER_MS`) prevent race conditions between the
Windows ICMP API timeout and the Tokio timeout.

## Customizing Timing (Library Users)

```rust
use ftr::{TimingConfig, TracerouteConfig};
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
    .timing(timing)
    .build()?;
```

## Integration Points

- **Async sockets** (`src/socket/linux.rs`, `macos.rs`, `bsd.rs`,
  `windows.rs`): receive a `TimingConfig` at construction and use
  `socket_read_timeout`, `receiver_poll_interval`, and `udp_retry_delay`.
- **Traceroute engine** (`src/traceroute/engine.rs`): uses
  `main_loop_poll_interval` and `enrichment_wait_time`.

## For Developers

When adding a new time-based operation:

1. Add a documented default constant to `src/config/timing.rs`
2. Add a corresponding field to `TimingConfig` with a doc link to the constant
3. Use the config field instead of hardcoding a delay
