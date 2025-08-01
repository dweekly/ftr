//! Factory for creating async probe sockets
//!
//! This module provides factory functions for creating async probe sockets
//! that use Tokio for immediate response notification.

use super::async_trait::{AsyncProbeSocket, ProbeMode};
use super::{ProbeProtocol, SocketMode};
use crate::TimingConfig;
use anyhow::{anyhow, Result};
use std::net::IpAddr;

/// Create an async probe socket for the given target
pub async fn create_async_probe_socket(
    target: IpAddr,
    timing_config: TimingConfig,
) -> Result<Box<dyn AsyncProbeSocket>> {
    create_async_probe_socket_with_options(target, timing_config, None, None).await
}

/// Create an async probe socket with protocol and mode preferences
pub async fn create_async_probe_socket_with_options(
    target: IpAddr,
    timing_config: TimingConfig,
    protocol: Option<ProbeProtocol>,
    _socket_mode: Option<SocketMode>,
) -> Result<Box<dyn AsyncProbeSocket>> {
    match target {
        IpAddr::V4(_) => {
            #[cfg(target_os = "windows")]
            {
                let _ = protocol; // Unused on Windows
                use super::windows_async_tokio::WindowsAsyncIcmpSocket;
                let socket = WindowsAsyncIcmpSocket::new_with_config(timing_config)?;

                // Print verbose mode info if requested
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
                let _ = protocol; // Unused on macOS
                use super::macos_async::MacOSAsyncIcmpSocket;
                let socket = MacOSAsyncIcmpSocket::new_with_config(timing_config)?;

                // Print verbose mode info if requested
                let verbose = std::env::var("FTR_VERBOSE")
                    .ok()
                    .and_then(|v| v.parse::<u8>().ok())
                    .unwrap_or(0);
                if verbose > 0 {
                    eprintln!("Using DGRAM ICMP mode for traceroute");
                }

                Ok(Box::new(socket))
            }

            #[cfg(target_os = "linux")]
            {
                // On Linux, check if ICMP was specifically requested
                match protocol {
                    Some(ProbeProtocol::Icmp) => {
                        // Check if we can create raw ICMP socket
                        use socket2::{Domain, Protocol, Socket, Type};
                        match Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)) {
                            Ok(_) => {
                                // We have permissions for raw ICMP
                                use super::linux_async::LinuxAsyncIcmpSocket;
                                let socket = LinuxAsyncIcmpSocket::new_with_config(timing_config)?;

                                // Print verbose mode info if requested
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
                                Err(anyhow!(
                                    "ICMP mode requires root or CAP_NET_RAW capability. \
                                    Try running with sudo or use UDP mode (--udp)"
                                ))
                            }
                            Err(e) => Err(anyhow!("Failed to create ICMP socket: {}", e)),
                        }
                    }
                    _ => {
                        // Default to UDP or when explicitly requested
                        use super::linux_async::LinuxAsyncUdpSocket;
                        let socket = LinuxAsyncUdpSocket::new_with_config(timing_config)?;

                        // Print verbose mode info if requested
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
            }

            #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
            {
                let _ = protocol; // Unused on other platforms
                                  // Placeholder for other platforms
                Err(anyhow!(
                    "Async socket implementation not yet available for this platform"
                ))
            }
        }
        IpAddr::V6(_) => Err(anyhow!("IPv6 is not yet supported")),
    }
}

/// Create an async probe socket with specific mode preference
pub async fn create_async_probe_socket_with_mode(
    target: IpAddr,
    timing_config: TimingConfig,
    preferred_mode: Option<ProbeMode>,
) -> Result<Box<dyn AsyncProbeSocket>> {
    // Check platform-specific mode support
    #[cfg(target_os = "windows")]
    {
        if let Some(mode) = preferred_mode {
            if mode != ProbeMode::WindowsIcmp {
                return Err(anyhow!(
                    "Only Windows ICMP mode is currently supported for async on Windows"
                ));
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let Some(mode) = preferred_mode {
            if mode != ProbeMode::DgramIcmp {
                return Err(anyhow!(
                    "Only DGRAM ICMP mode is currently supported for async on macOS"
                ));
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        if let Some(mode) = preferred_mode {
            if mode != ProbeMode::UdpWithRecverr {
                return Err(anyhow!(
                    "Only UDP with IP_RECVERR mode is currently supported for async on Linux"
                ));
            }
        }
    }

    create_async_probe_socket(target, timing_config).await
}
