//! Timing constants for traceroute operations
//!
//! This module defines the default timing parameters used throughout the
//! traceroute process. To tune timing at runtime, use
//! [`TimingConfig`](crate::TimingConfig) via
//! [`TracerouteConfigBuilder::timing`](crate::TracerouteConfigBuilder::timing).

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
