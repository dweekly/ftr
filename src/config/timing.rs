//! Timing configuration for traceroute operations
//!
//! This module defines timing parameters used throughout the traceroute process.

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Default socket read timeout in milliseconds
pub const DEFAULT_SOCKET_READ_TIMEOUT_MS: u64 = 50;

/// Default UDP retry delay in milliseconds
pub const DEFAULT_UDP_RETRY_DELAY_MS: u64 = 5;

/// Default receiver poll interval in milliseconds
pub const DEFAULT_RECEIVER_POLL_INTERVAL_MS: u64 = 1;

/// Default main loop poll interval in milliseconds
pub const DEFAULT_MAIN_LOOP_POLL_INTERVAL_MS: u64 = 5;

/// Default enrichment wait time in milliseconds
pub const DEFAULT_ENRICHMENT_WAIT_TIME_MS: u64 = 200;

/// Minimum socket read timeout for Windows in milliseconds
pub const WINDOWS_MIN_SOCKET_READ_TIMEOUT_MS: u32 = 100;

/// Minimum ICMP timeout for Windows in milliseconds
pub const WINDOWS_ICMP_MIN_TIMEOUT_MS: u32 = 100;

/// Minimum total timeout for Windows ICMP in milliseconds
pub const WINDOWS_ICMP_MIN_TOTAL_TIMEOUT_MS: u32 = 100;

/// Buffer added to Windows ICMP timeout to ensure Tokio timeout fires first
/// This prevents race conditions between Windows and Tokio timeouts
pub const WINDOWS_ICMP_TIMEOUT_BUFFER_MS: u32 = 50;

/// Timing configuration for traceroute operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingConfig {
    /// How long to wait for socket read operations
    pub socket_read_timeout: Duration,
    /// Delay between UDP retry attempts
    pub udp_retry_delay: Duration,
    /// How often to poll the receiver for responses
    pub receiver_poll_interval: Duration,
    /// How often to poll in the main loop
    pub main_loop_poll_interval: Duration,
    /// How long to wait for enrichment data
    pub enrichment_wait_time: Duration,
}

impl Default for TimingConfig {
    fn default() -> Self {
        Self {
            socket_read_timeout: Duration::from_millis(DEFAULT_SOCKET_READ_TIMEOUT_MS),
            udp_retry_delay: Duration::from_millis(DEFAULT_UDP_RETRY_DELAY_MS),
            receiver_poll_interval: Duration::from_millis(DEFAULT_RECEIVER_POLL_INTERVAL_MS),
            main_loop_poll_interval: Duration::from_millis(DEFAULT_MAIN_LOOP_POLL_INTERVAL_MS),
            enrichment_wait_time: Duration::from_millis(DEFAULT_ENRICHMENT_WAIT_TIME_MS),
        }
    }
}

impl TimingConfig {
    /// Create a new timing configuration with all values set to the same duration
    pub fn uniform(duration: Duration) -> Self {
        Self {
            socket_read_timeout: duration,
            udp_retry_delay: duration,
            receiver_poll_interval: duration,
            main_loop_poll_interval: duration,
            enrichment_wait_time: duration,
        }
    }

    /// Create a timing configuration optimized for fast local network traces
    pub fn fast() -> Self {
        Self {
            socket_read_timeout: Duration::from_millis(10),
            udp_retry_delay: Duration::from_millis(1),
            receiver_poll_interval: Duration::from_millis(1),
            main_loop_poll_interval: Duration::from_millis(1),
            enrichment_wait_time: Duration::from_millis(50),
        }
    }

    /// Create a timing configuration optimized for slow or unreliable networks
    pub fn slow() -> Self {
        Self {
            socket_read_timeout: Duration::from_millis(200),
            udp_retry_delay: Duration::from_millis(20),
            receiver_poll_interval: Duration::from_millis(5),
            main_loop_poll_interval: Duration::from_millis(10),
            enrichment_wait_time: Duration::from_millis(500),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_values() {
        let config = TimingConfig::default();
        assert_eq!(
            config.socket_read_timeout,
            Duration::from_millis(DEFAULT_SOCKET_READ_TIMEOUT_MS)
        );
        assert_eq!(
            config.udp_retry_delay,
            Duration::from_millis(DEFAULT_UDP_RETRY_DELAY_MS)
        );
        assert_eq!(
            config.receiver_poll_interval,
            Duration::from_millis(DEFAULT_RECEIVER_POLL_INTERVAL_MS)
        );
        assert_eq!(
            config.main_loop_poll_interval,
            Duration::from_millis(DEFAULT_MAIN_LOOP_POLL_INTERVAL_MS)
        );
        assert_eq!(
            config.enrichment_wait_time,
            Duration::from_millis(DEFAULT_ENRICHMENT_WAIT_TIME_MS)
        );
    }

    #[test]
    fn test_uniform_config() {
        let duration = Duration::from_millis(42);
        let config = TimingConfig::uniform(duration);
        assert_eq!(config.socket_read_timeout, duration);
        assert_eq!(config.udp_retry_delay, duration);
        assert_eq!(config.receiver_poll_interval, duration);
        assert_eq!(config.main_loop_poll_interval, duration);
        assert_eq!(config.enrichment_wait_time, duration);
    }

    #[test]
    fn test_fast_config() {
        let config = TimingConfig::fast();
        assert!(config.socket_read_timeout < Duration::from_millis(50));
        assert!(config.udp_retry_delay < Duration::from_millis(5));
        assert!(config.receiver_poll_interval < Duration::from_millis(5));
        assert!(config.main_loop_poll_interval < Duration::from_millis(5));
        assert!(config.enrichment_wait_time < Duration::from_millis(100));
    }

    #[test]
    fn test_slow_config() {
        let config = TimingConfig::slow();
        assert!(config.socket_read_timeout > Duration::from_millis(100));
        assert!(config.udp_retry_delay > Duration::from_millis(10));
        assert!(config.receiver_poll_interval > Duration::from_millis(2));
        assert!(config.main_loop_poll_interval > Duration::from_millis(5));
        assert!(config.enrichment_wait_time > Duration::from_millis(300));
    }
}
