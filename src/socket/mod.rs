//! Socket abstraction layer for multi-protocol traceroute support

#[cfg(any(
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
))]
pub(crate) mod bsd;
#[cfg(any(
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
))]
pub(crate) mod bsd_v6;
pub(crate) mod factory;
// The v4 ICMP codec's parse/build helpers are only consumed by the Unix
// socket paths; Windows probes through the Win32 ICMP API, which parses
// replies itself, so there they are compiled for their unit tests only.
#[cfg_attr(target_os = "windows", allow(dead_code))]
pub(crate) mod icmp;
// The ICMPv6 codec is platform-neutral and its unit tests run everywhere,
// but only the macOS, Linux, and BSD socket paths consume it — the Windows
// v6 path doesn't (the Icmp6SendEcho2 API parses replies itself), so
// silence dead_code elsewhere.
#[cfg_attr(
    not(any(
        target_os = "macos",
        target_os = "linux",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    )),
    allow(dead_code)
)]
pub(crate) mod icmpv6;
#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "linux")]
pub(crate) mod linux_v6;
#[cfg(target_os = "macos")]
pub(crate) mod macos;
#[cfg(target_os = "macos")]
pub(crate) mod macos_v6;
pub mod traits;
pub mod utils;
#[cfg(target_os = "windows")]
pub(crate) mod windows;
#[cfg(target_os = "windows")]
pub(crate) mod windows_v6;

use serde::{Deserialize, Serialize};

/// IP version to use for probing
///
/// IPv4 is supported on all platforms. IPv6 probing is supported on macOS
/// (unprivileged DGRAM ICMPv6), Linux (unprivileged UDP with
/// `IPV6_RECVERR` by default, ICMPv6 ping sockets where
/// `net.ipv4.ping_group_range` permits, raw ICMPv6 as root), Windows
/// (`Icmp6SendEcho2`, no elevation required), and the BSDs
/// (raw ICMPv6, root required — exercised by CI's FreeBSD VM; OpenBSD/
/// NetBSD/DragonFly are best-effort and untested); any remaining platform
/// returns
/// [`TracerouteError::Ipv6NotSupported`](crate::TracerouteError::Ipv6NotSupported)
/// for IPv6 targets.
///
/// This enum is `#[non_exhaustive]` so downstream matches must include a
/// wildcard arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
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
///
/// This enum is `#[non_exhaustive]`: new protocols may be added in minor
/// releases, so downstream matches must include a wildcard arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
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
///
/// This enum is `#[non_exhaustive]`: new socket modes may be added in minor
/// releases, so downstream matches must include a wildcard arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
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
}
