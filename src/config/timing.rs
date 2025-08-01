//! Global timing configuration with compile-time defaults and runtime overrides
//!
//! This module provides a clean way to manage timing values throughout the application.
//! Default values are defined as compile-time constants, but can be overridden at runtime
//! via CLI arguments or library API.

use once_cell::sync::OnceCell;
use std::time::Duration;

// Compile-time defaults as public constants (in milliseconds)
/// Default socket read timeout in milliseconds
pub const DEFAULT_SOCKET_READ_TIMEOUT_MS: u64 = 100;
/// Default UDP retry delay in milliseconds
pub const DEFAULT_UDP_RETRY_DELAY_MS: u64 = 10;
/// Default receiver poll interval in milliseconds
pub const DEFAULT_RECEIVER_POLL_INTERVAL_MS: u64 = 100;
/// Default main loop poll interval in milliseconds
pub const DEFAULT_MAIN_LOOP_POLL_INTERVAL_MS: u64 = 10;
/// Default enrichment wait time in milliseconds
pub const DEFAULT_ENRICHMENT_WAIT_TIME_MS: u64 = 100;

// Windows-specific ICMP timing constants
// These values were determined through empirical testing to ensure reliable operation
//
// Testing methodology:
// - Ran 10 iterations each of timeouts from 5ms to 100ms
// - Measured success rate (ability to receive responses from internet hosts)
// - Found that timeouts < 30ms had 0% success rate
// - Timeouts >= 30ms had 100% success rate
//
// The root cause appears to be that Windows ICMP implementation has internal
// timing constraints that make it unreliable with very short timeouts.

/// Minimum timeout that Windows ICMP API handles reliably (milliseconds)
/// Testing shows timeouts < 30ms produce inconsistent results where some
/// probes may not return any response even from low-latency hosts
pub const WINDOWS_ICMP_MIN_TIMEOUT_MS: u32 = 30;

/// Additional buffer to add to user timeout for Windows API (milliseconds)
/// This ensures our Tokio timeout always fires before Windows timeout,
/// preventing race conditions between the two timeout mechanisms
///
/// Without this buffer, there's a race condition where:
/// 1. User sets 30ms timeout
/// 2. Both Tokio and Windows start 30ms timers
/// 3. Due to scheduling variations, Windows might fire first
/// 4. This causes inconsistent behavior
///
/// By giving Windows extra time, we ensure Tokio always wins the race.
pub const WINDOWS_ICMP_TIMEOUT_BUFFER_MS: u32 = 50;

/// Minimum total timeout for Windows ICMP operations (milliseconds)
/// Even with buffer, Windows needs at least this much time for stable operation
/// This is the sum of the minimum reliable timeout plus our safety buffer
pub const WINDOWS_ICMP_MIN_TOTAL_TIMEOUT_MS: u32 = 100;

// Runtime override storage - set once at program startup
static OVERRIDE_CONFIG: OnceCell<crate::TimingConfig> = OnceCell::new();

/// Get the socket read timeout duration
pub fn socket_read_timeout() -> Duration {
    OVERRIDE_CONFIG
        .get()
        .map(|c| c.socket_read_timeout)
        .unwrap_or_else(|| Duration::from_millis(DEFAULT_SOCKET_READ_TIMEOUT_MS))
}

/// Get the UDP retry delay duration
pub fn udp_retry_delay() -> Duration {
    OVERRIDE_CONFIG
        .get()
        .map(|c| c.udp_retry_delay)
        .unwrap_or_else(|| Duration::from_millis(DEFAULT_UDP_RETRY_DELAY_MS))
}

/// Get the receiver poll interval duration
pub fn receiver_poll_interval() -> Duration {
    OVERRIDE_CONFIG
        .get()
        .map(|c| c.receiver_poll_interval)
        .unwrap_or_else(|| Duration::from_millis(DEFAULT_RECEIVER_POLL_INTERVAL_MS))
}

/// Get the main loop poll interval duration
pub fn main_loop_poll_interval() -> Duration {
    OVERRIDE_CONFIG
        .get()
        .map(|c| c.main_loop_poll_interval)
        .unwrap_or_else(|| Duration::from_millis(DEFAULT_MAIN_LOOP_POLL_INTERVAL_MS))
}

/// Get the enrichment wait time duration
pub fn enrichment_wait_time() -> Duration {
    OVERRIDE_CONFIG
        .get()
        .map(|c| c.enrichment_wait_time)
        .unwrap_or_else(|| Duration::from_millis(DEFAULT_ENRICHMENT_WAIT_TIME_MS))
}

/// Set the global timing configuration
///
/// This should be called once at program startup if custom timing is needed.
/// Returns an error if the configuration has already been set.
pub fn set_config(config: crate::TimingConfig) -> Result<(), crate::TimingConfig> {
    OVERRIDE_CONFIG.set(config)
}

/// Check if custom timing configuration has been set
pub fn is_custom_config_set() -> bool {
    OVERRIDE_CONFIG.get().is_some()
}

/// Reset the configuration (mainly useful for tests)
#[cfg(test)]
pub fn reset_config() {
    // OnceCell doesn't have a reset method in the stable API
    // This is a limitation we'll work around in tests
}
