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

/// Check if running as root
fn is_root() -> bool {
    #[cfg(target_os = "linux")]
    {
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(all(unix, not(target_os = "linux")))]
    {
        // For other Unix systems, check if we can create a raw socket
        // This is a heuristic since we don't have libc on non-Linux
        Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)).is_ok()
    }
    #[cfg(not(unix))]
    {
        // On Windows, check if we can create a raw ICMP socket
        Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)).is_ok()
    }
}

/// Represents the compatibility of a socket mode on a given OS
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Compatibility {
    /// Works without any special privileges
    Works,
    /// Requires root/administrator privileges
    RequiresRoot,
    /// Not supported on this OS
    NotSupported,
}

/// Get the compatibility of a socket mode for the current OS
fn get_compatibility(protocol: ProbeProtocol, socket_mode: SocketMode) -> Compatibility {
    use Compatibility::*;

    #[cfg(target_os = "linux")]
    {
        match (protocol, socket_mode) {
            (ProbeProtocol::Icmp, SocketMode::Raw) => RequiresRoot,
            (ProbeProtocol::Icmp, SocketMode::Dgram) => Works, // Requires ping group
            (ProbeProtocol::Udp, SocketMode::Raw) => RequiresRoot,
            (ProbeProtocol::Udp, SocketMode::Dgram) => Works, // Works with IP_RECVERR
            (ProbeProtocol::Tcp, SocketMode::Raw) => RequiresRoot,
            (ProbeProtocol::Tcp, SocketMode::Stream) => Works,
            _ => NotSupported,
        }
    }

    #[cfg(target_os = "macos")]
    {
        match (protocol, socket_mode) {
            (ProbeProtocol::Icmp, SocketMode::Raw) => RequiresRoot,
            (ProbeProtocol::Icmp, SocketMode::Dgram) => Works,
            (ProbeProtocol::Udp, SocketMode::Raw) => RequiresRoot,
            (ProbeProtocol::Udp, SocketMode::Dgram) => RequiresRoot, // Needs raw ICMP receive
            (ProbeProtocol::Tcp, SocketMode::Raw) => RequiresRoot,
            (ProbeProtocol::Tcp, SocketMode::Stream) => Works,
            _ => NotSupported,
        }
    }

    #[cfg(target_os = "freebsd")]
    {
        match (protocol, socket_mode) {
            (ProbeProtocol::Icmp, SocketMode::Raw) => RequiresRoot,
            (ProbeProtocol::Icmp, SocketMode::Dgram) => Works,
            (ProbeProtocol::Udp, SocketMode::Raw) => RequiresRoot,
            (ProbeProtocol::Udp, SocketMode::Dgram) => RequiresRoot, // Needs raw ICMP receive
            (ProbeProtocol::Tcp, SocketMode::Raw) => RequiresRoot,
            (ProbeProtocol::Tcp, SocketMode::Stream) => Works,
            _ => NotSupported,
        }
    }

    #[cfg(target_os = "openbsd")]
    {
        match (protocol, socket_mode) {
            (ProbeProtocol::Icmp, SocketMode::Raw) => RequiresRoot,
            (ProbeProtocol::Icmp, SocketMode::Dgram) => NotSupported, // OpenBSD doesn't have DGRAM ICMP
            (ProbeProtocol::Udp, SocketMode::Raw) => RequiresRoot,
            (ProbeProtocol::Udp, SocketMode::Dgram) => RequiresRoot, // Needs raw ICMP receive
            (ProbeProtocol::Tcp, SocketMode::Raw) => RequiresRoot,
            (ProbeProtocol::Tcp, SocketMode::Stream) => Works,
            _ => NotSupported,
        }
    }

    #[cfg(target_os = "windows")]
    {
        match (protocol, socket_mode) {
            (ProbeProtocol::Icmp, SocketMode::Raw) => Works, // Windows allows raw ICMP
            (ProbeProtocol::Icmp, SocketMode::Dgram) => NotSupported,
            (ProbeProtocol::Udp, SocketMode::Raw) => RequiresRoot,
            (ProbeProtocol::Udp, SocketMode::Dgram) => RequiresRoot, // Needs raw ICMP receive
            (ProbeProtocol::Tcp, SocketMode::Raw) => RequiresRoot,
            (ProbeProtocol::Tcp, SocketMode::Stream) => Works,
            _ => NotSupported,
        }
    }

    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "windows"
    )))]
    {
        // Unknown OS - be conservative
        match (protocol, socket_mode) {
            (ProbeProtocol::Icmp, SocketMode::Raw) => RequiresRoot,
            (ProbeProtocol::Tcp, SocketMode::Stream) => Works,
            _ => NotSupported,
        }
    }
}

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
    create_probe_socket_with_options(target, preferred_protocol, preferred_mode, false)
}

/// Creates a probe socket with the specified options including verbose output.
pub fn create_probe_socket_with_options(
    target: IpAddr,
    preferred_protocol: Option<ProbeProtocol>,
    preferred_mode: Option<SocketMode>,
    verbose: bool,
) -> Result<Box<dyn ProbeSocket>> {
    let ip_version = match target {
        IpAddr::V4(_) => IpVersion::V4,
        IpAddr::V6(_) => IpVersion::V6,
    };

    let running_as_root = is_root();
    let user_specified_protocol = preferred_protocol.is_some();
    let user_specified_mode = preferred_mode.is_some();

    // If user specified both protocol and mode, validate compatibility first
    if let (Some(protocol), Some(socket_mode)) = (preferred_protocol, preferred_mode) {
        let compatibility = get_compatibility(protocol, socket_mode);
        match compatibility {
            Compatibility::NotSupported => {
                return Err(anyhow!(
                    "{} mode is not supported for {} protocol on {}",
                    socket_mode.description(),
                    protocol.description(),
                    std::env::consts::OS
                ));
            }
            Compatibility::RequiresRoot if !running_as_root => {
                return Err(anyhow!(
                    "{} mode for {} protocol requires root privileges on {}. Try running with sudo.",
                    socket_mode.description(),
                    protocol.description(),
                    std::env::consts::OS
                ));
            }
            _ => {} // Works or RequiresRoot with root - proceed
        }
    }

    // Determine protocols to try
    let protocols = match preferred_protocol {
        Some(p) => vec![p],
        None => {
            // Order protocols by preference based on OS and privileges
            if running_as_root {
                // With root, prefer ICMP for best results
                vec![ProbeProtocol::Icmp, ProbeProtocol::Udp, ProbeProtocol::Tcp]
            } else {
                // Without root, prefer protocols that work unprivileged
                #[cfg(target_os = "linux")]
                {
                    // Linux: UDP works without root via IP_RECVERR
                    vec![ProbeProtocol::Udp, ProbeProtocol::Icmp, ProbeProtocol::Tcp]
                }
                #[cfg(any(target_os = "macos", target_os = "freebsd"))]
                {
                    // macOS/FreeBSD: DGRAM ICMP works without root
                    vec![ProbeProtocol::Icmp, ProbeProtocol::Tcp, ProbeProtocol::Udp]
                }
                #[cfg(target_os = "windows")]
                {
                    // Windows: Raw ICMP works without admin
                    vec![ProbeProtocol::Icmp, ProbeProtocol::Tcp, ProbeProtocol::Udp]
                }
                #[cfg(not(any(
                    target_os = "linux",
                    target_os = "macos",
                    target_os = "freebsd",
                    target_os = "windows"
                )))]
                {
                    // Unknown OS: try TCP first as it's most likely to work
                    vec![ProbeProtocol::Tcp, ProbeProtocol::Icmp, ProbeProtocol::Udp]
                }
            }
        }
    };

    let mut last_error = None;

    for protocol in protocols {
        // Determine socket modes to try based on compatibility
        let socket_modes = match preferred_mode {
            Some(mode) => vec![mode], // User specified a mode, only try that one
            None => {
                // Get all possible modes for this protocol and filter by compatibility
                let possible_modes = match protocol {
                    ProbeProtocol::Icmp => vec![SocketMode::Raw, SocketMode::Dgram],
                    ProbeProtocol::Udp => vec![SocketMode::Dgram, SocketMode::Raw],
                    ProbeProtocol::Tcp => vec![SocketMode::Stream, SocketMode::Raw],
                };

                let mut compatible_modes = Vec::new();
                for mode in possible_modes {
                    match get_compatibility(protocol, mode) {
                        Compatibility::Works => compatible_modes.push(mode),
                        Compatibility::RequiresRoot if running_as_root => {
                            compatible_modes.push(mode)
                        }
                        _ => {} // Skip NotSupported or RequiresRoot without root
                    }
                }

                // If no compatible modes, skip this protocol
                if compatible_modes.is_empty() {
                    if verbose && user_specified_protocol {
                        eprintln!(
                            "No compatible socket modes for {} protocol on {} {}",
                            protocol.description(),
                            std::env::consts::OS,
                            if running_as_root {
                                "(running as root)"
                            } else {
                                "(non-root)"
                            }
                        );
                    }
                    continue;
                }

                compatible_modes
            }
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
                    if verbose {
                        eprintln!("Using {} mode for traceroute", mode.description());
                    }

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
                                    if verbose {
                                        eprintln!("Using UDP with IP_RECVERR (no root required)");
                                    }
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
                            } else if verbose {
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
        // Build OS-specific error message
        #[cfg(any(target_os = "macos", target_os = "freebsd"))]
        let os_name = std::env::consts::OS;
        let running_as_root = is_root();

        let cmd = std::env::args().collect::<Vec<_>>().join(" ");

        #[cfg(target_os = "linux")]
        let error_msg = if running_as_root {
            "Failed to create any probe socket even with root privileges. This may be a system configuration issue.".to_string()
        } else {
            format!(
                "Failed to create any probe socket. On Linux, you can:\n\
                 1. Run with sudo: sudo {}\n\
                 2. Configure ping group: sudo sysctl -w net.ipv4.ping_group_range=\"0 65535\"\n\
                 3. Use UDP mode which works without root via IP_RECVERR",
                cmd
            )
        };

        #[cfg(any(target_os = "macos", target_os = "freebsd"))]
        let error_msg = if running_as_root {
            "Failed to create any probe socket even with root privileges. This may be a system configuration issue.".to_string()
        } else {
            format!(
                "Failed to create any probe socket. On {os_name}, DGRAM ICMP mode works without root.\n\
                 If it's not working, try running with sudo: sudo {cmd}"
            )
        };

        #[cfg(target_os = "openbsd")]
        let error_msg = if running_as_root {
            "Failed to create any probe socket even with root privileges. This may be a system configuration issue.".to_string()
        } else {
            format!(
                "Failed to create any probe socket. On OpenBSD, raw sockets require root.\n\
                 Run with doas/sudo: doas {} or sudo {}",
                cmd, cmd
            )
        };

        #[cfg(target_os = "windows")]
        let error_msg = "Failed to create any probe socket. On Windows, ensure you have administrator privileges.".to_string();

        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "freebsd", target_os = "openbsd", target_os = "windows")))]
        let error_msg = format!(
            "Failed to create any probe socket. This operating system may require root privileges.\n\
             Try running with sudo: sudo {}",
            cmd
        );

        Err(anyhow!(error_msg))
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
