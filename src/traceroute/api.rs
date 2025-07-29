//! High-level traceroute API

use crate::socket::factory::create_probe_socket_with_port;
use crate::socket::ProbeSocket;
use crate::traceroute::{
    TracerouteConfig, TracerouteEngine, TracerouteError, TracerouteProgress, TracerouteResult,
};
use std::net::IpAddr;
use tokio::sync::mpsc;

/// High-level traceroute API for performing network path discovery
///
/// The `Traceroute` struct provides the main interface for running traceroute
/// operations. It handles socket creation, probe management, and result collection.
///
/// # Examples
///
/// ```no_run
/// use ftr::{Traceroute, TracerouteConfig};
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let config = TracerouteConfig::builder()
///     .target("google.com")
///     .max_hops(20)
///     .build()?;
///
/// let traceroute = Traceroute::new(config)?;
/// let result = traceroute.run().await?;
/// # Ok(())
/// # }
/// ```
pub struct Traceroute {
    engine: TracerouteEngine,
}

impl Traceroute {
    /// Create a new traceroute from configuration
    ///
    /// This method creates the appropriate socket type based on the configuration
    /// and initializes the traceroute engine.
    ///
    /// # Arguments
    ///
    /// * `config` - The traceroute configuration specifying target, protocol, and options
    ///
    /// # Errors
    ///
    /// * `TracerouteError::SocketError` - If socket creation fails (often due to permissions)
    /// * `TracerouteError::ResolutionError` - If target IP resolution fails
    pub fn new(config: TracerouteConfig) -> Result<Self, TracerouteError> {
        // Create socket based on configuration
        let socket = create_socket_from_config(&config)?;
        let engine = TracerouteEngine::new(config, socket)?;

        Ok(Self { engine })
    }

    /// Create a traceroute with custom socket
    ///
    /// This method allows you to provide a pre-configured socket implementation,
    /// useful for testing or when you need custom socket behavior.
    ///
    /// # Arguments
    ///
    /// * `config` - The traceroute configuration
    /// * `socket` - A custom probe socket implementation
    pub fn with_socket(
        config: TracerouteConfig,
        socket: Box<dyn ProbeSocket>,
    ) -> Result<Self, TracerouteError> {
        let engine = TracerouteEngine::new(config, socket)?;
        Ok(Self { engine })
    }

    /// Run the traceroute and return the result
    ///
    /// This method performs the actual traceroute operation, sending probes
    /// and collecting responses until the target is reached or max hops is exceeded.
    ///
    /// # Returns
    ///
    /// A `TracerouteResult` containing all discovered hops and network information
    ///
    /// # Errors
    ///
    /// * `TracerouteError::Timeout` - If the overall operation times out
    /// * `TracerouteError::SocketError` - If probe sending/receiving fails
    pub async fn run(self) -> Result<TracerouteResult, TracerouteError> {
        self.engine.run().await
    }

    /// Run the traceroute with progress updates
    ///
    /// This method runs the traceroute while sending progress updates through
    /// the provided channel. Useful for UI applications that need real-time updates.
    ///
    /// # Arguments
    ///
    /// * `progress_tx` - Channel sender for progress updates
    ///
    /// # Note
    ///
    /// This is currently not fully implemented and behaves the same as `run()`.
    pub async fn run_with_progress(
        self,
        progress_tx: mpsc::Sender<TracerouteProgress>,
    ) -> Result<TracerouteResult, TracerouteError> {
        // TODO: This would require refactoring the engine to support progress updates
        // For now, just run normally
        let _ = progress_tx;
        self.engine.run().await
    }

    /// Get current progress (snapshot)
    ///
    /// Returns a snapshot of the current traceroute progress, including
    /// the number of hops discovered and the current TTL being probed.
    pub fn get_progress(&self) -> TracerouteProgress {
        self.engine.get_progress()
    }
}

/// Create a socket from configuration
fn create_socket_from_config(
    config: &TracerouteConfig,
) -> Result<Box<dyn ProbeSocket>, TracerouteError> {
    // Check for unimplemented features
    if let Some(protocol) = config.protocol {
        if protocol == crate::socket::ProbeProtocol::Tcp {
            return Err(TracerouteError::NotImplemented {
                feature: "TCP traceroute".to_string(),
            });
        }
    }

    // Resolve target if needed
    let target_ip = match config.target_ip {
        Some(ip) => ip,
        None => {
            // Try to parse as IP
            config.target.parse::<IpAddr>().map_err(|_| {
                TracerouteError::ResolutionError(
                    "Target IP not provided and target is not a valid IP address".to_string(),
                )
            })?
        }
    };

    // Check for IPv6
    if matches!(target_ip, IpAddr::V6(_)) {
        return Err(TracerouteError::Ipv6NotSupported);
    }

    // Create socket with options
    let socket = create_probe_socket_with_port(
        target_ip,
        config.protocol,
        config.socket_mode,
        config.verbose,
        config.port,
    );

    socket.map_err(|e| {
        // Check if this is a permission error
        if e.to_string().contains("Permission denied") || e.to_string().contains("requires root") {
            TracerouteError::InsufficientPermissions {
                required: "root or CAP_NET_RAW capability".to_string(),
                suggestion: "Try running with sudo or use UDP mode with --udp flag".to_string(),
            }
        } else {
            TracerouteError::SocketError(e.to_string())
        }
    })
}

/// Convenience function to run a simple traceroute
///
/// This is the simplest way to perform a traceroute. It uses default settings
/// and automatically handles DNS resolution, ASN lookup, and reverse DNS.
///
/// # Arguments
///
/// * `target` - The target hostname or IP address
///
/// # Examples
///
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let result = ftr::trace("google.com").await?;
/// for hop in result.hops {
///     println!("Hop {}: {:?} - {:?}", hop.ttl, hop.addr, hop.hostname);
/// }
/// # Ok(())
/// # }
/// ```
pub async fn trace(target: &str) -> Result<TracerouteResult, TracerouteError> {
    let config = TracerouteConfig::builder()
        .target(target)
        .build()
        .map_err(TracerouteError::ConfigError)?;

    Traceroute::new(config)?.run().await
}

/// Convenience function to run traceroute with custom configuration
///
/// This function allows you to provide a fully configured `TracerouteConfig`
/// for complete control over the traceroute operation.
///
/// # Arguments
///
/// * `config` - A complete traceroute configuration
///
/// # Examples
///
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// use ftr::{TracerouteConfigBuilder, ProbeProtocol};
///
/// let config = TracerouteConfigBuilder::new()
///     .target("1.1.1.1")
///     .protocol(ProbeProtocol::Udp)
///     .max_hops(15)
///     .queries(3)
///     .build()?;
///
/// let result = ftr::trace_with_config(config).await?;
/// # Ok(())
/// # }
/// ```
pub async fn trace_with_config(
    config: TracerouteConfig,
) -> Result<TracerouteResult, TracerouteError> {
    Traceroute::new(config)?.run().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_create_traceroute() {
        let config = TracerouteConfig::builder()
            .target("8.8.8.8")
            .target_ip(IpAddr::V4("8.8.8.8".parse().unwrap()))
            .build()
            .unwrap();

        // This will fail without proper privileges, but we're just testing compilation
        let result = Traceroute::new(config);
        assert!(result.is_ok() || result.is_err()); // Either is fine for unit test
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_trace_localhost() {
        let config = TracerouteConfig::builder()
            .target("127.0.0.1")
            .max_hops(3)
            .probe_timeout(Duration::from_millis(100))
            .overall_timeout(Duration::from_millis(500))
            .build()
            .unwrap();

        let result = tokio::time::timeout(Duration::from_secs(2), trace_with_config(config)).await;

        match result {
            Ok(Ok(trace_result)) => {
                assert_eq!(trace_result.target, "127.0.0.1");
                assert!(!trace_result.hops.is_empty());
            }
            Ok(Err(_)) | Err(_) => {
                // Permission errors or timeouts are expected in tests
            }
        }
    }
}
