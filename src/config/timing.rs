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
