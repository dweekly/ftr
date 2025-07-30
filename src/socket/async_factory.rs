//! Factory for creating async probe sockets
//!
//! This module provides factory functions for creating async probe sockets
//! that use Tokio for immediate response notification.

use super::async_trait::{AsyncProbeSocket, ProbeMode};
use crate::TimingConfig;
use anyhow::{anyhow, Result};
use std::net::IpAddr;

/// Create an async probe socket for the given target
pub async fn create_async_probe_socket(
    target: IpAddr,
    timing_config: TimingConfig,
) -> Result<Box<dyn AsyncProbeSocket>> {
    match target {
        IpAddr::V4(_) => {
            #[cfg(target_os = "windows")]
            {
                use super::windows_async_tokio::WindowsAsyncIcmpSocket;
                let socket = WindowsAsyncIcmpSocket::new_with_config(timing_config)?;
                Ok(Box::new(socket))
            }
            
            #[cfg(not(target_os = "windows"))]
            {
                // Placeholder for other platforms
                Err(anyhow!("Async socket implementation not yet available for this platform"))
            }
        }
        IpAddr::V6(_) => {
            Err(anyhow!("IPv6 is not yet supported"))
        }
    }
}

/// Create an async probe socket with specific mode preference
pub async fn create_async_probe_socket_with_mode(
    target: IpAddr,
    timing_config: TimingConfig,
    preferred_mode: Option<ProbeMode>,
) -> Result<Box<dyn AsyncProbeSocket>> {
    // For now, we only support Windows ICMP mode
    #[cfg(target_os = "windows")]
    {
        if let Some(mode) = preferred_mode {
            if mode != ProbeMode::WindowsIcmp {
                return Err(anyhow!("Only Windows ICMP mode is currently supported for async"));
            }
        }
    }
    
    create_async_probe_socket(target, timing_config).await
}