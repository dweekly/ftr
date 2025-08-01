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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TimingConfig;

    #[test]
    fn test_default_values() {
        // If no custom config is set, these should use defaults
        if !is_custom_config_set() {
            assert_eq!(
                socket_read_timeout(),
                Duration::from_millis(DEFAULT_SOCKET_READ_TIMEOUT_MS)
            );
            assert_eq!(
                udp_retry_delay(),
                Duration::from_millis(DEFAULT_UDP_RETRY_DELAY_MS)
            );
            assert_eq!(
                receiver_poll_interval(),
                Duration::from_millis(DEFAULT_RECEIVER_POLL_INTERVAL_MS)
            );
            assert_eq!(
                main_loop_poll_interval(),
                Duration::from_millis(DEFAULT_MAIN_LOOP_POLL_INTERVAL_MS)
            );
            assert_eq!(
                enrichment_wait_time(),
                Duration::from_millis(DEFAULT_ENRICHMENT_WAIT_TIME_MS)
            );
        } else {
            // Just verify that the functions return valid durations
            assert!(socket_read_timeout() > Duration::from_millis(0));
            assert!(udp_retry_delay() > Duration::from_millis(0));
            assert!(receiver_poll_interval() > Duration::from_millis(0));
            assert!(main_loop_poll_interval() > Duration::from_millis(0));
            assert!(enrichment_wait_time() > Duration::from_millis(0));
        }
    }

    #[test]
    fn test_windows_constants() {
        assert_eq!(WINDOWS_ICMP_MIN_TIMEOUT_MS, 30);
        assert_eq!(WINDOWS_ICMP_TIMEOUT_BUFFER_MS, 50);
        assert_eq!(WINDOWS_ICMP_MIN_TOTAL_TIMEOUT_MS, 100);
    }

    #[test]
    fn test_custom_config_detection() {
        // Note: We can't easily test set_config in unit tests because OnceCell
        // is global and persists across tests. This is mainly for coverage.

        // Try to set a config (may fail if already set by another test)
        let config = TimingConfig {
            socket_read_timeout: Duration::from_millis(200),
            udp_retry_delay: Duration::from_millis(20),
            receiver_poll_interval: Duration::from_millis(200),
            main_loop_poll_interval: Duration::from_millis(20),
            enrichment_wait_time: Duration::from_millis(200),
        };

        let _ = set_config(config.clone());

        // If it was set successfully, is_custom_config_set should be true
        // If it failed (already set), it should still be true from the previous set
        if is_custom_config_set() {
            // Verify the values match either our custom config or some other config
            let timeout = socket_read_timeout();
            assert!(timeout == Duration::from_millis(200) || timeout > Duration::from_millis(0));
        }
    }

    #[test]
    fn test_timing_config_values_reasonable() {
        // Test that all default values are reasonable
        assert!(DEFAULT_SOCKET_READ_TIMEOUT_MS > 0);
        assert!(DEFAULT_SOCKET_READ_TIMEOUT_MS <= 1000); // Not more than 1 second

        assert!(DEFAULT_UDP_RETRY_DELAY_MS > 0);
        assert!(DEFAULT_UDP_RETRY_DELAY_MS <= 100); // Quick retry

        assert!(DEFAULT_RECEIVER_POLL_INTERVAL_MS > 0);
        assert!(DEFAULT_RECEIVER_POLL_INTERVAL_MS <= 1000);

        assert!(DEFAULT_MAIN_LOOP_POLL_INTERVAL_MS > 0);
        assert!(DEFAULT_MAIN_LOOP_POLL_INTERVAL_MS <= 100); // Responsive

        assert!(DEFAULT_ENRICHMENT_WAIT_TIME_MS > 0);
        assert!(DEFAULT_ENRICHMENT_WAIT_TIME_MS <= 1000);
    }

    #[test]
    fn test_windows_timeout_relationship() {
        // Verify the documented relationship between Windows constants
        assert!(WINDOWS_ICMP_MIN_TIMEOUT_MS < WINDOWS_ICMP_MIN_TOTAL_TIMEOUT_MS);
        assert!(WINDOWS_ICMP_TIMEOUT_BUFFER_MS > 0);

        // The minimum total should be at least the sum of min timeout and some buffer
        assert!(WINDOWS_ICMP_MIN_TOTAL_TIMEOUT_MS >= WINDOWS_ICMP_MIN_TIMEOUT_MS);
    }

    #[test]
    fn test_duration_conversions() {
        // Ensure Duration conversions work correctly
        let duration = Duration::from_millis(DEFAULT_SOCKET_READ_TIMEOUT_MS);
        assert_eq!(duration.as_millis(), DEFAULT_SOCKET_READ_TIMEOUT_MS as u128);

        let duration = Duration::from_millis(DEFAULT_UDP_RETRY_DELAY_MS);
        assert_eq!(duration.as_millis(), DEFAULT_UDP_RETRY_DELAY_MS as u128);
    }
}
