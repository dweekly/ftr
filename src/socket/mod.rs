//! Socket abstraction layer for multi-protocol traceroute support

use anyhow::Result;
use std::net::IpAddr;
use std::time::{Duration, Instant};

pub mod factory;
#[cfg(not(target_os = "windows"))]
pub mod icmp_v4;
#[cfg(not(target_os = "windows"))]
pub mod udp;
#[cfg(target_os = "windows")]
pub mod windows;
#[cfg(target_os = "windows")]
pub mod windows_async;

use serde::{Deserialize, Serialize};

/// IP version to use for probing
///
/// Currently only IPv4 is fully supported. IPv6 support is planned for future releases.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IpVersion {
    /// IPv4 addressing
    V4,
    /// IPv6 addressing (not yet fully supported)
    V6,
}

/// Protocol to use for probing
///
/// Different protocols have different advantages:
/// - **ICMP**: Most accurate, but often requires root privileges
/// - **UDP**: Works without root on some systems, good compatibility
///
/// # Note
///
/// TCP support is planned for a future release but not yet implemented.
///
/// # Examples
///
/// ```
/// use ftr::ProbeProtocol;
///
/// let protocol = ProbeProtocol::Udp;
/// println!("Using {} protocol", protocol.description());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProbeProtocol {
    /// ICMP Echo Request protocol
    Icmp,
    /// UDP protocol with high port numbers
    Udp,
    /// TCP SYN packets (not yet implemented)
    Tcp,
}

impl ProbeProtocol {
    /// Get a human-readable description
    pub fn description(&self) -> &'static str {
        match self {
            ProbeProtocol::Icmp => "ICMP",
            ProbeProtocol::Udp => "UDP",
            ProbeProtocol::Tcp => "TCP",
        }
    }
}

/// Socket mode (affects permissions required)
///
/// Different socket modes have different permission requirements:
/// - **Raw**: Full control but requires root/CAP_NET_RAW
/// - **Dgram**: ICMP datagram sockets - platform specific permissions
/// - **Stream**: TCP connections (not yet implemented)
///
/// The library will automatically fall back to less privileged modes when possible.
///
/// # Platform-Specific DGRAM Support
///
/// - **Linux**: Requires root or `sysctl net.ipv4.ping_group_range` configuration
/// - **macOS**: Works without root for ICMP DGRAM sockets
/// - **FreeBSD/OpenBSD**: Requires root
/// - **Windows**: Uses Windows-specific ICMP APIs (IcmpSendEcho)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SocketMode {
    /// Raw socket - always requires CAP_NET_RAW or root
    Raw,
    /// Datagram socket for ICMP - permissions vary by platform
    Dgram,
    /// Stream socket (TCP) - not yet implemented
    Stream,
}

impl SocketMode {
    /// Get a human-readable description
    pub fn description(&self) -> &'static str {
        match self {
            SocketMode::Raw => "Raw",
            SocketMode::Dgram => "Datagram",
            SocketMode::Stream => "Stream",
        }
    }
}

/// Combined probe configuration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeMode {
    /// IP version to use (IPv4 or IPv6)
    pub ip_version: IpVersion,
    /// Protocol to use for probing (ICMP, UDP, or TCP)
    pub protocol: ProbeProtocol,
    /// Socket mode that determines permissions required
    pub socket_mode: SocketMode,
}

impl ProbeMode {
    /// Get a human-readable description of this mode
    pub fn description(&self) -> String {
        format!(
            "{} {} {}",
            match self.socket_mode {
                SocketMode::Raw => "Raw",
                SocketMode::Dgram => "Datagram",
                SocketMode::Stream => "Stream",
            },
            match self.protocol {
                ProbeProtocol::Icmp => match self.ip_version {
                    IpVersion::V4 => "ICMP",
                    IpVersion::V6 => "ICMPv6",
                },
                ProbeProtocol::Udp => "UDP",
                ProbeProtocol::Tcp => "TCP",
            },
            match self.ip_version {
                IpVersion::V4 => "IPv4",
                IpVersion::V6 => "IPv6",
            }
        )
    }
}

/// Information about a sent probe
#[derive(Debug, Clone)]
pub struct ProbeInfo {
    /// Time-to-live value
    pub ttl: u8,
    /// Unique identifier for this probe
    pub identifier: u16,
    /// Sequence number
    pub sequence: u16,
    /// When the probe was sent
    pub sent_at: Instant,
}

/// Type of response received
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponseType {
    /// ICMP Time Exceeded (TTL expired)
    TimeExceeded,
    /// ICMP Destination Unreachable
    DestinationUnreachable(u8), // with ICMP code
    /// ICMP Echo Reply
    EchoReply,
    /// TCP SYN-ACK received
    TcpSynAck,
    /// TCP RST received
    TcpRst,
    /// UDP port unreachable
    UdpPortUnreachable,
}

/// Response from a probe
#[derive(Debug, Clone)]
pub struct ProbeResponse {
    /// Address that sent the response
    pub from_addr: IpAddr,
    /// Type of response
    pub response_type: ResponseType,
    /// Probe information that triggered this response
    pub probe_info: ProbeInfo,
    /// Round-trip time
    pub rtt: Duration,
}

/// Trait for probe sockets
pub trait ProbeSocket: Send + Sync {
    /// Get the mode this socket is operating in
    fn mode(&self) -> ProbeMode;

    /// Set the TTL for outgoing packets
    fn set_ttl(&self, ttl: u8) -> Result<()>;

    /// Send a probe to the target
    fn send_probe(&self, target: IpAddr, probe_info: ProbeInfo) -> Result<()>;

    /// Try to receive a response with timeout
    fn recv_response(&self, timeout: Duration) -> Result<Option<ProbeResponse>>;

    /// Check if destination has been reached
    fn destination_reached(&self) -> bool;

    /// Set timing configuration for the socket
    /// This allows the socket to use configuration-driven timeouts instead of hardcoded values
    fn set_timing_config(&mut self, config: &crate::TimingConfig) -> Result<()> {
        // Default implementation does nothing for backward compatibility
        let _ = config;
        Ok(())
    }
}

/// Trait for creating probe sockets with fallback
pub trait ProbeSocketFactory {
    /// Try to create a probe socket for the given target
    /// Will automatically fall back to less privileged modes
    fn create_socket(
        target: IpAddr,
        preferred_protocol: Option<ProbeProtocol>,
    ) -> Result<Box<dyn ProbeSocket>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_probe_mode_description() {
        let mode = ProbeMode {
            ip_version: IpVersion::V4,
            protocol: ProbeProtocol::Icmp,
            socket_mode: SocketMode::Dgram,
        };
        assert_eq!(mode.description(), "Datagram ICMP IPv4");

        let mode = ProbeMode {
            ip_version: IpVersion::V6,
            protocol: ProbeProtocol::Udp,
            socket_mode: SocketMode::Raw,
        };
        assert_eq!(mode.description(), "Raw UDP IPv6");
    }

    #[test]
    fn test_ip_version() {
        assert_eq!(IpVersion::V4, IpVersion::V4);
        assert_ne!(IpVersion::V4, IpVersion::V6);
    }

    #[test]
    fn test_response_types() {
        let resp = ResponseType::DestinationUnreachable(3);
        match resp {
            ResponseType::DestinationUnreachable(code) => assert_eq!(code, 3),
            _ => panic!("Wrong response type"),
        }
    }
}
