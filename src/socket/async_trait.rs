//! Async trait for probe sockets
//!
//! This module defines the async interface for probe sockets, enabling
//! immediate response processing and eliminating polling delays.

use crate::probe::{ProbeInfo, ProbeResponse};
use anyhow::Result;
use async_trait::async_trait;
use std::net::IpAddr;

/// Probe mode supported by the socket
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeMode {
    /// ICMP echo requests using DGRAM sockets (Linux/macOS)
    DgramIcmp,
    /// ICMP echo requests using Windows IcmpSendEcho2 API
    WindowsIcmp,
    /// UDP probes with IP_RECVERR (Linux)
    UdpWithRecverr,
    /// Raw ICMP sockets (fallback)
    RawIcmp,
}

/// Async trait for probe sockets
///
/// This trait defines the interface for all async probe socket implementations.
/// It enables immediate response processing without polling delays.
#[async_trait]
pub trait AsyncProbeSocket: Send + Sync {
    /// Get the probe mode this socket supports
    fn mode(&self) -> ProbeMode;

    /// Send a probe and get a future for its response
    ///
    /// This method sends a probe and returns a future that will resolve
    /// to the response when it arrives. This allows immediate wake-up
    /// when the response is received.
    async fn send_probe_and_recv(&self, dest: IpAddr, probe: ProbeInfo) -> Result<ProbeResponse>;

    /// Check if the destination has been reached
    ///
    /// Returns true if we've received a response indicating we've reached
    /// the final destination (e.g., ICMP Echo Reply).
    fn destination_reached(&self) -> bool;

    /// Get the number of pending probes
    ///
    /// Returns the number of probes that have been sent but not yet
    /// received a response or timed out.
    fn pending_count(&self) -> usize;
}
