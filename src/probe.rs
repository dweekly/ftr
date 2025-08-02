//! Probe-related types for async traceroute
//!
//! This module contains types used by the async implementation to avoid
//! circular dependencies with the socket module.

use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Information about a probe to be sent
#[derive(Debug, Clone, Copy)]
pub struct ProbeInfo {
    /// Sequence number for this probe
    pub sequence: u16,
    /// Time-to-live value
    pub ttl: u8,
    /// When the probe was sent
    pub sent_at: Instant,
}

/// Response from a probe
#[derive(Debug, Clone)]
pub struct ProbeResponse {
    /// Address that sent the response
    pub from_addr: IpAddr,
    /// Sequence number of the probe that triggered this response
    pub sequence: u16,
    /// TTL value that was used
    pub ttl: u8,
    /// Round-trip time
    pub rtt: Duration,
    /// When the response was received
    pub received_at: Instant,
    /// Whether this response indicates we've reached the destination
    pub is_destination: bool,
    /// Whether this is a timeout response
    pub is_timeout: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_probe_info_creation() {
        let now = Instant::now();
        let probe = ProbeInfo {
            sequence: 1234,
            ttl: 64,
            sent_at: now,
        };

        assert_eq!(probe.sequence, 1234);
        assert_eq!(probe.ttl, 64);
        assert_eq!(probe.sent_at, now);
    }

    #[test]
    fn test_probe_response_creation() {
        let now = Instant::now();
        let addr = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let response = ProbeResponse {
            from_addr: addr,
            sequence: 5678,
            ttl: 10,
            rtt: Duration::from_millis(25),
            received_at: now,
            is_destination: false,
            is_timeout: false,
        };

        assert_eq!(response.from_addr, addr);
        assert_eq!(response.sequence, 5678);
        assert_eq!(response.ttl, 10);
        assert_eq!(response.rtt, Duration::from_millis(25));
        assert_eq!(response.received_at, now);
        assert!(!response.is_destination);
        assert!(!response.is_timeout);
    }

    #[test]
    fn test_probe_info_copy() {
        let probe1 = ProbeInfo {
            sequence: 100,
            ttl: 32,
            sent_at: Instant::now(),
        };

        let probe2 = probe1; // Copy
        assert_eq!(probe1.sequence, probe2.sequence);
        assert_eq!(probe1.ttl, probe2.ttl);
        assert_eq!(probe1.sent_at, probe2.sent_at);
    }

    #[test]
    fn test_probe_response_clone() {
        let response1 = ProbeResponse {
            from_addr: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            sequence: 999,
            ttl: 5,
            rtt: Duration::from_millis(100),
            received_at: Instant::now(),
            is_destination: true,
            is_timeout: false,
        };

        let response2 = response1.clone();
        assert_eq!(response1.from_addr, response2.from_addr);
        assert_eq!(response1.sequence, response2.sequence);
        assert_eq!(response1.ttl, response2.ttl);
        assert_eq!(response1.rtt, response2.rtt);
        assert_eq!(response1.is_destination, response2.is_destination);
        assert_eq!(response1.is_timeout, response2.is_timeout);
    }

    #[test]
    fn test_timeout_response() {
        let response = ProbeResponse {
            from_addr: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            sequence: 1,
            ttl: 1,
            rtt: Duration::from_secs(1),
            received_at: Instant::now(),
            is_destination: false,
            is_timeout: true,
        };

        assert!(response.is_timeout);
        assert!(!response.is_destination);
    }

    #[test]
    fn test_destination_response() {
        let response = ProbeResponse {
            from_addr: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            sequence: 1,
            ttl: 255,
            rtt: Duration::from_millis(10),
            received_at: Instant::now(),
            is_destination: true,
            is_timeout: false,
        };

        assert!(response.is_destination);
        assert!(!response.is_timeout);
    }

    #[test]
    fn test_probe_info_debug() {
        let probe = ProbeInfo {
            sequence: 42,
            ttl: 128,
            sent_at: Instant::now(),
        };

        let debug_str = format!("{:?}", probe);
        assert!(debug_str.contains("sequence: 42"));
        assert!(debug_str.contains("ttl: 128"));
    }

    #[test]
    fn test_probe_response_debug() {
        let response = ProbeResponse {
            from_addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            sequence: 100,
            ttl: 20,
            rtt: Duration::from_millis(50),
            received_at: Instant::now(),
            is_destination: false,
            is_timeout: false,
        };

        let debug_str = format!("{:?}", response);
        assert!(debug_str.contains("192.168.1.1"));
        assert!(debug_str.contains("sequence: 100"));
        assert!(debug_str.contains("ttl: 20"));
    }
}
