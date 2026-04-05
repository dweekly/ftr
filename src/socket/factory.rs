//! Factory for creating probe sockets
//!
//! This module provides factory functions for creating probe sockets
//! that use Tokio for immediate response notification.

use super::traits::{ProbeMode, ProbeSocket};
use super::{ProbeProtocol, SocketMode};
use crate::traceroute::TracerouteError;
use crate::TimingConfig;
use std::net::IpAddr;

/// Create a probe socket for the given target
pub async fn create_probe_socket(
    target: IpAddr,
    timing_config: TimingConfig,
) -> Result<Box<dyn ProbeSocket>, TracerouteError> {
    create_probe_socket_with_options(target, timing_config, None, None).await
}

/// Create a probe socket with protocol and mode preferences
pub async fn create_probe_socket_with_options(
    target: IpAddr,
    timing_config: TimingConfig,
    protocol: Option<ProbeProtocol>,
    socket_mode: Option<SocketMode>,
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
                let socket = WindowsAsyncIcmpSocket::new_with_config(timing_config)?;

                let verbose = std::env::var("FTR_VERBOSE")
                    .ok()
                    .and_then(|v| v.parse::<u8>().ok())
                    .unwrap_or(0);
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
                let socket = MacOSAsyncIcmpSocket::new_with_config(timing_config)?;

                let verbose = std::env::var("FTR_VERBOSE")
                    .ok()
                    .and_then(|v| v.parse::<u8>().ok())
                    .unwrap_or(0);
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

                            let verbose = std::env::var("FTR_VERBOSE")
                                .ok()
                                .and_then(|v| v.parse::<u8>().ok())
                                .unwrap_or(0);
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

                    let verbose = std::env::var("FTR_VERBOSE")
                        .ok()
                        .and_then(|v| v.parse::<u8>().ok())
                        .unwrap_or(0);
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

                let verbose = std::env::var("FTR_VERBOSE")
                    .ok()
                    .and_then(|v| v.parse::<u8>().ok())
                    .unwrap_or(0);
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
                Err(TracerouteError::SocketError(
                    "Socket implementation not available for this platform".to_string(),
                ))
            }
        }
        IpAddr::V6(_) => Err(TracerouteError::Ipv6NotSupported),
    }
}

/// Create a probe socket with specific mode preference
pub async fn create_probe_socket_with_mode(
    target: IpAddr,
    timing_config: TimingConfig,
    preferred_mode: Option<ProbeMode>,
) -> Result<Box<dyn ProbeSocket>, TracerouteError> {
    #[cfg(target_os = "windows")]
    if let Some(mode) = preferred_mode {
        if mode != ProbeMode::WindowsIcmp {
            return Err(TracerouteError::SocketError(
                "Only Windows ICMP mode is supported on Windows".to_string(),
            ));
        }
    }

    #[cfg(target_os = "macos")]
    if let Some(mode) = preferred_mode {
        if mode != ProbeMode::DgramIcmp {
            return Err(TracerouteError::SocketError(
                "Only DGRAM ICMP mode is supported on macOS".to_string(),
            ));
        }
    }

    #[cfg(target_os = "linux")]
    if let Some(mode) = preferred_mode {
        if mode != ProbeMode::UdpWithRecverr {
            return Err(TracerouteError::SocketError(
                "Only UDP with IP_RECVERR mode is supported on Linux".to_string(),
            ));
        }
    }

    #[cfg(any(
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    ))]
    if let Some(mode) = preferred_mode {
        if mode != ProbeMode::RawIcmp {
            return Err(TracerouteError::SocketError(
                "Only Raw ICMP mode is supported on BSD systems".to_string(),
            ));
        }
    }

    create_probe_socket(target, timing_config).await
}
