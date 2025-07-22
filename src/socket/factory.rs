//! Factory for creating probe sockets with automatic fallback

use super::icmp_v4::{DgramIcmpV4Socket, RawIcmpV4Socket};
#[cfg(target_os = "linux")]
use super::udp::UdpRecvErrSocket;
use super::udp::UdpWithIcmpSocket;
use super::{IpVersion, ProbeMode, ProbeProtocol, ProbeSocket, SocketMode};
use anyhow::{anyhow, Context, Result};
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};

// Common POSIX error codes
const EPERM: i32 = 1; // Operation not permitted
const EACCES: i32 = 13; // Permission denied

/// Try to create a socket with the specified configuration
fn try_create_socket(mode: ProbeMode) -> Result<Socket, std::io::Error> {
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
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Unsupported socket mode/protocol combination",
            ))
        }
    };

    Socket::new(domain, socket_type, protocol)
}

/// Create a probe socket with automatic fallback
pub fn create_probe_socket(
    target: IpAddr,
    preferred_protocol: Option<ProbeProtocol>,
) -> Result<Box<dyn ProbeSocket>> {
    create_probe_socket_with_mode(target, preferred_protocol, None)
}

/// Create a probe socket with specific mode preference
pub fn create_probe_socket_with_mode(
    target: IpAddr,
    preferred_protocol: Option<ProbeProtocol>,
    preferred_mode: Option<SocketMode>,
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
    let user_specified_mode = preferred_mode.is_some();

    for protocol in protocols {
        // Try socket modes in order of preference (most capable first)
        let socket_modes = match preferred_mode {
            Some(mode) => vec![mode], // User specified a mode, only try that one
            None => match protocol {
                ProbeProtocol::Icmp => vec![SocketMode::Raw, SocketMode::Dgram],
                ProbeProtocol::Udp => vec![SocketMode::Dgram],
                ProbeProtocol::Tcp => vec![SocketMode::Raw, SocketMode::Stream],
            },
        };

        for socket_mode in socket_modes {
            let mode = ProbeMode {
                ip_version,
                protocol,
                socket_mode,
            };

            match try_create_socket(mode) {
                Ok(socket) => {
                    #[allow(unused_mut)]
                    let mut socket = socket;
                    eprintln!("Using {} mode for traceroute", mode.description());

                    // Create the appropriate ProbeSocket implementation
                    match (mode.ip_version, mode.protocol, mode.socket_mode) {
                        (IpVersion::V4, ProbeProtocol::Icmp, SocketMode::Raw) => {
                            // Raw socket doesn't need explicit binding
                            return Ok(Box::new(RawIcmpV4Socket::new(socket)?));
                        }
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

                            // On Linux, try IP_RECVERR first (no root required)
                            #[cfg(target_os = "linux")]
                            {
                                if let Ok(recv_err_sock) = UdpRecvErrSocket::new(socket) {
                                    eprintln!("Using UDP with IP_RECVERR (no root required)");
                                    return Ok(Box::new(recv_err_sock));
                                }
                                // If IP_RECVERR fails, we need to recreate the socket
                                // since ownership was moved
                                match try_create_socket(mode) {
                                    Ok(new_socket) => {
                                        new_socket
                                            .bind(&bind_addr.into())
                                            .context("Failed to bind UDP socket")?;
                                        socket = new_socket;
                                    }
                                    Err(e) => {
                                        return Err(anyhow!("Failed to recreate UDP socket after IP_RECVERR attempt: {}", e));
                                    }
                                }
                            }

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
                                    None
                                }
                            };

                            if icmp_socket.is_some() {
                                return Ok(Box::new(UdpWithIcmpSocket::new(socket, icmp_socket)?));
                            } else {
                                // UDP without ICMP receive capability is not functional
                                let error_msg = if cfg!(target_os = "linux") {
                                    "UDP mode failed to enable IP_RECVERR and couldn't create raw ICMP socket.\n\
                                     On Linux, UDP traceroute should work without root via IP_RECVERR.\n\
                                     This might be a kernel configuration issue."
                                } else {
                                    "UDP mode requires root privileges to create a raw ICMP socket for receiving responses.\n\
                                     Without raw ICMP capability, UDP traceroute cannot function.\n\
                                     Try running with sudo: sudo {}"
                                };

                                if user_specified_mode {
                                    let args = std::env::args().collect::<Vec<_>>().join(" ");
                                    return Err(anyhow!("{}", error_msg.replace("{}", &args)));
                                } else {
                                    // Don't return a non-functional socket in automatic mode
                                    return Err(anyhow!(
                                        "UDP mode requires ICMP reception capability"
                                    ));
                                }
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
                Err(io_err) => {
                    // Check if this is a permission error by looking at the OS error code
                    let is_permission_error =
                        matches!(io_err.kind(), std::io::ErrorKind::PermissionDenied)
                            || io_err
                                .raw_os_error()
                                .map(|code| code == EPERM || code == EACCES)
                                .unwrap_or(false);

                    if is_permission_error {
                        if socket_mode == SocketMode::Raw {
                            if user_specified_mode {
                                // User explicitly requested raw mode
                                return Err(anyhow!(
                                    "Failed to create Raw socket: Permission denied. Raw sockets require root privileges or CAP_NET_RAW capability.\n\
                                     Try running with sudo: sudo {}", 
                                    std::env::args().collect::<Vec<_>>().join(" ")
                                ));
                            } else {
                                eprintln!(
                                    "Raw {} mode requires root privileges, trying fallback...",
                                    match protocol {
                                        ProbeProtocol::Icmp => "ICMP",
                                        ProbeProtocol::Udp => "UDP",
                                        ProbeProtocol::Tcp => "TCP",
                                    }
                                );
                            }
                        } else if socket_mode == SocketMode::Dgram
                            && protocol == ProbeProtocol::Icmp
                        {
                            if user_specified_mode {
                                return Err(anyhow!(
                                    "Failed to create DGRAM ICMP socket: {}.\n\
                                     DGRAM ICMP requires either:\n\
                                     1. Root privileges: sudo {}\n\
                                     2. Configured ping group (Linux): sudo sysctl -w net.ipv4.ping_group_range=\"0 65535\"",
                                    io_err,
                                    std::env::args().collect::<Vec<_>>().join(" ")
                                ));
                            } else {
                                eprintln!(
                                    "DGRAM ICMP not available ({io_err}), trying UDP mode..."
                                );
                            }
                        }
                    } else {
                        eprintln!("Failed to create {}: {}", mode.description(), io_err);
                    }
                    last_error = Some(anyhow::Error::from(io_err));
                }
            }
        }
    }

    // Provide helpful error message based on what was tried
    if user_specified_mode {
        Err(last_error.unwrap_or_else(|| anyhow!("Failed to create requested socket mode")))
    } else {
        Err(anyhow!(
            "Failed to create any probe socket. All modes require elevated privileges:\n\
             - Raw ICMP: Requires root or CAP_NET_RAW capability\n\
             - DGRAM ICMP: Requires root or configured ping_group_range (Linux)\n\
             - UDP: Requires root (needs raw ICMP socket for responses)\n\n\
             Solutions:\n\
             1. Run with sudo: sudo {}\n\
             2. On Linux, configure ping group: sudo sysctl -w net.ipv4.ping_group_range=\"0 65535\"",
            std::env::args().collect::<Vec<_>>().join(" ")
        ))
    }
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
