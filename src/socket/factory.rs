//! Factory for creating probe sockets
//!
//! This module provides factory functions for creating probe sockets
//! that use Tokio for immediate response notification.

use super::traits::ProbeSocket;
use super::{ProbeProtocol, SocketMode};
use crate::TimingConfig;
use crate::traceroute::TracerouteError;
use std::net::IpAddr;

/// Create a probe socket with protocol and mode preferences and a verbosity level
///
/// `verbose` controls diagnostic output on stderr (0 = silent, 1+ = print
/// the selected socket mode); it is threaded through explicitly rather than
/// read from the environment so concurrent traces cannot affect each other.
pub async fn create_probe_socket_with_options_and_verbose(
    target: IpAddr,
    timing_config: TimingConfig,
    protocol: Option<ProbeProtocol>,
    socket_mode: Option<SocketMode>,
    verbose: u8,
) -> Result<Box<dyn ProbeSocket>, TracerouteError> {
    // Check for unsupported protocols
    if let Some(ProbeProtocol::Tcp) = protocol {
        return Err(TracerouteError::NotImplemented {
            feature: "TCP traceroute".to_string(),
        });
    }

    match target {
        IpAddr::V4(_) => {
            #[cfg(target_os = "windows")]
            {
                let _ = protocol;
                let _ = socket_mode;
                use super::windows::WindowsAsyncIcmpSocket;
                let socket =
                    WindowsAsyncIcmpSocket::new_with_config_and_verbose(timing_config, verbose)?;

                if verbose > 0 {
                    eprintln!("Using Windows ICMP API mode for traceroute");
                }

                Ok(Box::new(socket))
            }

            #[cfg(target_os = "macos")]
            {
                let _ = protocol;
                let _ = socket_mode;
                use super::macos::MacOSAsyncIcmpSocket;
                let socket =
                    MacOSAsyncIcmpSocket::new_with_config_and_verbose(timing_config, verbose)?;

                if verbose > 0 {
                    eprintln!("Using DGRAM ICMP mode for traceroute (per-probe version)");
                }

                Ok(Box::new(socket))
            }

            #[cfg(target_os = "linux")]
            {
                let use_icmp = matches!(protocol, Some(ProbeProtocol::Icmp))
                    || matches!(socket_mode, Some(SocketMode::Raw));

                if use_icmp {
                    use socket2::{Domain, Protocol, Socket, Type};
                    match Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)) {
                        Ok(_) => {
                            use super::linux::LinuxAsyncIcmpSocket;
                            let socket = LinuxAsyncIcmpSocket::new_with_config(timing_config)?;

                            if verbose > 0 {
                                eprintln!("Using Raw ICMP mode for traceroute");
                            }

                            Ok(Box::new(socket))
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                            Err(TracerouteError::InsufficientPermissions {
                                required: "root or CAP_NET_RAW".to_string(),
                                suggestion: "Run with sudo or use UDP mode".to_string(),
                            })
                        }
                        Err(e) => Err(TracerouteError::SocketError(format!(
                            "Failed to create ICMP socket: {e}"
                        ))),
                    }
                } else {
                    use super::linux::LinuxAsyncUdpSocket;
                    let socket = LinuxAsyncUdpSocket::new_with_config(timing_config)?;

                    if verbose > 0 {
                        eprintln!("Using UDP with IP_RECVERR (no root required)");
                    }

                    Ok(Box::new(socket))
                }
            }

            #[cfg(any(
                target_os = "freebsd",
                target_os = "openbsd",
                target_os = "netbsd",
                target_os = "dragonfly"
            ))]
            {
                let _ = protocol;
                let _ = socket_mode;
                use super::bsd::BsdAsyncIcmpSocket;
                let socket = BsdAsyncIcmpSocket::new_with_config(timing_config)?;

                if verbose > 0 {
                    eprintln!("Using Raw ICMP mode for traceroute");
                }

                Ok(Box::new(socket))
            }

            #[cfg(not(any(
                target_os = "windows",
                target_os = "macos",
                target_os = "linux",
                target_os = "freebsd",
                target_os = "openbsd",
                target_os = "netbsd",
                target_os = "dragonfly"
            )))]
            {
                let _ = protocol;
                let _ = verbose;
                Err(TracerouteError::SocketError(
                    "Socket implementation not available for this platform".to_string(),
                ))
            }
        }
        IpAddr::V6(_) => {
            #[cfg(target_os = "macos")]
            {
                let _ = socket_mode;
                // Only ICMPv6 probing exists on macOS so far.
                if let Some(ProbeProtocol::Udp) = protocol {
                    return Err(TracerouteError::NotImplemented {
                        feature: "UDP IPv6 traceroute on macOS".to_string(),
                    });
                }
                use super::macos_v6::MacOSAsyncIcmpV6Socket;
                let socket =
                    MacOSAsyncIcmpV6Socket::new_with_config_and_verbose(timing_config, verbose)?;

                if verbose > 0 {
                    eprintln!("Using DGRAM ICMPv6 mode for traceroute (per-probe version)");
                }

                Ok(Box::new(socket))
            }

            #[cfg(target_os = "linux")]
            {
                create_linux_v6_socket(timing_config, protocol, socket_mode, verbose)
            }

            // Windows/BSD IPv6 probing is planned (see docs/IPV6_DESIGN.md
            // open questions); until each platform's behavior is
            // spike-validated, report the typed error.
            #[cfg(not(any(target_os = "macos", target_os = "linux")))]
            {
                let _ = (timing_config, socket_mode, verbose);
                Err(TracerouteError::Ipv6NotSupported)
            }
        }
    }
}

/// Linux IPv6 socket selection, mirroring the IPv4 preference handling.
///
/// Explicit preferences are honored: `SocketMode::Raw` forces the raw
/// ICMPv6 socket (root/`CAP_NET_RAW`), `ProbeProtocol::Icmp` prefers the
/// unprivileged ICMPv6 ping socket (gated by `net.ipv4.ping_group_range`)
/// with a raw fallback, and `ProbeProtocol::Udp` forces the `IPV6_RECVERR`
/// mode. With no preference the fallback chain is
/// UDP6-`IPV6_RECVERR` (unprivileged, default sysctls) -> ICMPv6 ping
/// socket -> raw ICMPv6 — validated mode behavior is recorded in
/// `docs/IPV6_DESIGN.md`.
#[cfg(target_os = "linux")]
fn create_linux_v6_socket(
    timing_config: TimingConfig,
    protocol: Option<ProbeProtocol>,
    socket_mode: Option<SocketMode>,
    verbose: u8,
) -> Result<Box<dyn ProbeSocket>, TracerouteError> {
    use super::linux_v6::{
        LinuxAsyncPingV6Socket, LinuxAsyncRawIcmpV6Socket, LinuxAsyncUdpV6Socket,
    };

    let make_udp = |tc: TimingConfig| -> Result<Box<dyn ProbeSocket>, TracerouteError> {
        let socket = LinuxAsyncUdpV6Socket::new_with_config(tc)?;
        if verbose > 0 {
            eprintln!("Using UDP with IPV6_RECVERR (no root required)");
        }
        Ok(Box::new(socket))
    };
    let make_ping = |tc: TimingConfig| -> Result<Box<dyn ProbeSocket>, TracerouteError> {
        let socket = LinuxAsyncPingV6Socket::new_with_config(tc)?;
        if verbose > 0 {
            eprintln!("Using ICMPv6 ping-socket mode for traceroute");
        }
        Ok(Box::new(socket))
    };
    let make_raw = |tc: TimingConfig| -> Result<Box<dyn ProbeSocket>, TracerouteError> {
        let socket = LinuxAsyncRawIcmpV6Socket::new_with_config(tc)?;
        if verbose > 0 {
            eprintln!("Using raw ICMPv6 mode for traceroute");
        }
        Ok(Box::new(socket))
    };

    // Explicit raw mode: succeed as root/CAP_NET_RAW or surface the typed
    // permission error.
    if matches!(socket_mode, Some(SocketMode::Raw)) {
        return make_raw(timing_config);
    }

    match protocol {
        // Explicit ICMP: ping socket first (unprivileged where the sysctl
        // allows), then raw. If both fail, report the ping-socket error —
        // it carries the ping_group_range suggestion.
        Some(ProbeProtocol::Icmp) => match make_ping(timing_config.clone()) {
            Ok(socket) => Ok(socket),
            Err(ping_err) => make_raw(timing_config).map_err(|_| ping_err),
        },
        // Explicit UDP: the IPV6_RECVERR mode, no fallback.
        Some(ProbeProtocol::Udp) => make_udp(timing_config),
        // Auto: UDP6-RECVERR -> ping socket -> raw. UDP needs no special
        // privileges, so the later stages only matter on unusual systems.
        _ => match make_udp(timing_config.clone()) {
            Ok(socket) => Ok(socket),
            Err(udp_err) => match make_ping(timing_config.clone()) {
                Ok(socket) => Ok(socket),
                Err(_) => make_raw(timing_config).map_err(|_| udp_err),
            },
        },
    }
}
