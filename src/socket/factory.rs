//! Factory for creating probe sockets with automatic fallback

use super::icmp_v4::DgramIcmpV4Socket;
use super::udp::{UdpProbeSocket, UdpWithIcmpSocket};
use super::{IpVersion, ProbeMode, ProbeProtocol, ProbeSocket, SocketMode};
use anyhow::{anyhow, Context, Result};
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};

/// Try to create a socket with the specified configuration
fn try_create_socket(mode: ProbeMode) -> Result<Socket> {
    let domain = match mode.ip_version {
        IpVersion::V4 => Domain::IPV4,
        IpVersion::V6 => Domain::IPV6,
    };

    let (socket_type, protocol) = match (mode.socket_mode, mode.protocol) {
        (SocketMode::Raw, ProbeProtocol::Icmp) => {
            let proto = match mode.ip_version {
                IpVersion::V4 => Protocol::ICMPV4,
                IpVersion::V6 => Protocol::ICMPV6,
            };
            (Type::RAW, Some(proto))
        }
        (SocketMode::Dgram, ProbeProtocol::Icmp) => {
            let proto = match mode.ip_version {
                IpVersion::V4 => Protocol::ICMPV4,
                IpVersion::V6 => Protocol::ICMPV6,
            };
            (Type::DGRAM, Some(proto))
        }
        (SocketMode::Dgram, ProbeProtocol::Udp) => (Type::DGRAM, Some(Protocol::UDP)),
        (SocketMode::Raw, ProbeProtocol::Udp) => {
            // For receiving ICMP responses to UDP probes
            let proto = match mode.ip_version {
                IpVersion::V4 => Protocol::ICMPV4,
                IpVersion::V6 => Protocol::ICMPV6,
            };
            (Type::RAW, Some(proto))
        }
        (SocketMode::Stream, ProbeProtocol::Tcp) => (Type::STREAM, Some(Protocol::TCP)),
        (SocketMode::Raw, ProbeProtocol::Tcp) => (Type::RAW, Some(Protocol::TCP)),
        _ => return Err(anyhow!("Unsupported socket mode/protocol combination")),
    };

    Socket::new(domain, socket_type, protocol)
        .with_context(|| format!("Failed to create socket for {}", mode.description()))
}

/// Create a probe socket with automatic fallback
pub fn create_probe_socket(
    target: IpAddr,
    preferred_protocol: Option<ProbeProtocol>,
) -> Result<Box<dyn ProbeSocket>> {
    let ip_version = match target {
        IpAddr::V4(_) => IpVersion::V4,
        IpAddr::V6(_) => IpVersion::V6,
    };

    // Determine protocols to try
    let protocols = match preferred_protocol {
        Some(p) => vec![p],
        None => vec![ProbeProtocol::Icmp, ProbeProtocol::Udp, ProbeProtocol::Tcp],
    };

    let mut last_error = None;

    for protocol in protocols {
        // Try socket modes in order of preference (most capable first)
        let socket_modes = match protocol {
            ProbeProtocol::Icmp => vec![SocketMode::Raw, SocketMode::Dgram],
            ProbeProtocol::Udp => vec![SocketMode::Dgram],
            ProbeProtocol::Tcp => vec![SocketMode::Raw, SocketMode::Stream],
        };

        for socket_mode in socket_modes {
            let mode = ProbeMode {
                ip_version,
                protocol,
                socket_mode,
            };

            match try_create_socket(mode) {
                Ok(socket) => {
                    eprintln!("Using {} mode for traceroute", mode.description());

                    // Create the appropriate ProbeSocket implementation
                    match (mode.ip_version, mode.protocol, mode.socket_mode) {
                        (IpVersion::V4, ProbeProtocol::Icmp, SocketMode::Dgram) => {
                            // Bind the socket
                            let bind_addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0);
                            socket
                                .bind(&bind_addr.into())
                                .context("Failed to bind ICMP socket")?;

                            return Ok(Box::new(DgramIcmpV4Socket::new(socket)?));
                        }
                        (IpVersion::V4, ProbeProtocol::Udp, SocketMode::Dgram) => {
                            // Bind UDP socket
                            let bind_addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0);
                            socket
                                .bind(&bind_addr.into())
                                .context("Failed to bind UDP socket")?;

                            // Try to create a raw ICMP socket for receiving responses
                            let icmp_socket = match Socket::new(
                                Domain::IPV4,
                                Type::RAW,
                                Some(Protocol::ICMPV4),
                            ) {
                                Ok(s) => {
                                    let _ = s.bind(&bind_addr.into());
                                    Some(s)
                                }
                                Err(_) => {
                                    eprintln!(
                                        "Warning: Could not create raw ICMP socket for UDP mode"
                                    );
                                    eprintln!("UDP traceroute will have limited functionality");
                                    None
                                }
                            };

                            if icmp_socket.is_some() {
                                return Ok(Box::new(UdpWithIcmpSocket::new(socket, icmp_socket)?));
                            } else {
                                return Ok(Box::new(UdpProbeSocket::new(socket)?));
                            }
                        }
                        _ => {
                            // Other implementations not yet available
                            return Err(anyhow!(
                                "Socket implementation for {} not yet available",
                                mode.description()
                            ));
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Failed to create {}: {}", mode.description(), e);
                    last_error = Some(e);
                }
            }
        }
    }

    Err(last_error.unwrap_or_else(|| anyhow!("Failed to create any probe socket")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_ip_version_detection() {
        let ipv4 = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let ipv6 = IpAddr::V6("2001:db8::1".parse().unwrap());

        // IPv4 ICMP DGRAM might succeed if we have permissions
        // or fail if we don't - both are valid outcomes
        let _ = create_probe_socket(ipv4, None);

        // IPv6 not implemented yet
        assert!(create_probe_socket(ipv6, None).is_err());
    }

    #[test]
    fn test_mode_combinations() {
        // Test valid combinations
        let valid_modes = vec![
            ProbeMode {
                ip_version: IpVersion::V4,
                protocol: ProbeProtocol::Icmp,
                socket_mode: SocketMode::Raw,
            },
            ProbeMode {
                ip_version: IpVersion::V4,
                protocol: ProbeProtocol::Icmp,
                socket_mode: SocketMode::Dgram,
            },
            ProbeMode {
                ip_version: IpVersion::V4,
                protocol: ProbeProtocol::Udp,
                socket_mode: SocketMode::Dgram,
            },
        ];

        for mode in valid_modes {
            // Just test that try_create_socket doesn't panic
            // It may fail due to permissions, but shouldn't panic
            let _ = try_create_socket(mode);
        }
    }

    #[test]
    fn test_udp_fallback() {
        let ipv4 = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));

        // Try to create with UDP preference
        // This should succeed without special permissions
        let result = create_probe_socket(ipv4, Some(ProbeProtocol::Udp));

        // UDP should work (though may have limited functionality without raw ICMP)
        if result.is_ok() {
            eprintln!("UDP socket created successfully");
        } else {
            eprintln!("UDP socket creation failed (may be due to test environment)");
        }
    }
}
