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
