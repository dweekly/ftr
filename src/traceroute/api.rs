//! Async high-level traceroute API
//!
//! This module provides the async API for performing traceroute operations
//! with immediate response processing using Tokio.

use crate::dns::resolver;
use crate::services::Services;
use crate::socket::factory::create_probe_socket_with_options_and_verbose;
use crate::traceroute::engine::TracerouteEngine;
use crate::traceroute::{TracerouteConfig, TracerouteError, TracerouteResult};
use std::net::IpAddr;

/// Async traceroute API
#[derive(Debug)]
pub struct Traceroute {
    config: TracerouteConfig,
    target_ip: IpAddr,
    services: Option<Services>,
}

impl Traceroute {
    /// Create a new async traceroute from configuration with injected services
    pub async fn new_with_services(
        mut config: TracerouteConfig,
        services: Services,
    ) -> Result<Self, TracerouteError> {
        let target_ip = Self::resolve_target(&mut config).await?;

        Ok(Self {
            config,
            target_ip,
            services: Some(services),
        })
    }

    /// Resolve the target hostname/IP to an IpAddr
    async fn resolve_target(config: &mut TracerouteConfig) -> Result<IpAddr, TracerouteError> {
        // Check if target is an IP address literal
        if let Ok(ip) = config.target.parse::<IpAddr>() {
            if ip.is_ipv6() {
                return Err(TracerouteError::Ipv6NotSupported);
            }
            config.target_ip = Some(ip);
            return Ok(ip);
        }

        // Handle well-known hostnames
        if config.target == "localhost" {
            let ip = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
            config.target_ip = Some(ip);
            return Ok(ip);
        }

        // Already resolved
        if let Some(ip) = config.target_ip {
            return Ok(ip);
        }

        // Resolve hostname to IPv4 via DNS
        let addrs = resolver::resolve_a(&config.target)
            .await
            .map_err(|e| TracerouteError::ResolutionError(e.to_string()))?;

        let ip =
            IpAddr::V4(*addrs.first().ok_or_else(|| {
                TracerouteError::ResolutionError("No addresses found".to_string())
            })?);

        config.target_ip = Some(ip);
        Ok(ip)
    }

    /// Create a new async traceroute from configuration (uses global caches)
    pub async fn new(mut config: TracerouteConfig) -> Result<Self, TracerouteError> {
        let target_ip = Self::resolve_target(&mut config).await?;

        Ok(Self {
            config,
            target_ip,
            services: None,
        })
    }

    /// Run the async traceroute
    pub async fn run(self) -> Result<TracerouteResult, TracerouteError> {
        // Use timing config from traceroute config, but override socket_read_timeout with probe_timeout
        let mut timing_config = self.config.timing.clone();
        timing_config.socket_read_timeout = self.config.probe_timeout;

        // Create socket with protocol preference; verbosity is passed
        // explicitly (never via environment variables, which would race
        // between concurrent traces in the same process)
        let socket = create_probe_socket_with_options_and_verbose(
            self.target_ip,
            timing_config,
            self.config.protocol,
            self.config.socket_mode,
            self.config.verbose,
        )
        .await?;

        // Create and run fully parallel async engine. Engine errors are
        // already TracerouteError values; propagate them unchanged so typed
        // variants (e.g. Ipv6NotSupported, InsufficientPermissions) survive.
        let engine = if let Some(services) = self.services {
            TracerouteEngine::new_with_services(
                socket,
                self.config.clone(),
                self.target_ip,
                std::sync::Arc::new(services),
            )
            .await?
        } else {
            TracerouteEngine::new(socket, self.config.clone(), self.target_ip).await?
        };

        let result = engine.run().await?;

        // The fully parallel engine handles enrichment internally, so we can just return
        Ok(result)
    }
}

/// Run an async traceroute with the given configuration
pub async fn trace_async(target: &str) -> Result<TracerouteResult, TracerouteError> {
    // ConfigError converts into TracerouteError::ConfigError via #[from]
    let config = TracerouteConfig::builder().target(target).build()?;
    trace_with_config_async(config).await
}

/// Run an async traceroute with a custom configuration
pub async fn trace_with_config_async(
    config: TracerouteConfig,
) -> Result<TracerouteResult, TracerouteError> {
    let traceroute = Traceroute::new(config).await?;
    traceroute.run().await
}

/// Run an async traceroute with injected services (internal API for Ftr struct)
pub(crate) async fn trace_with_services(
    config: TracerouteConfig,
    services: &Services,
) -> Result<TracerouteResult, TracerouteError> {
    let traceroute = Traceroute::new_with_services(config, services.clone()).await?;
    traceroute.run().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn test_async_traceroute_creation() {
        let config = TracerouteConfig::builder()
            .target("127.0.0.1")
            .build()
            .unwrap();

        let result = Traceroute::new(config).await;
        assert!(result.is_ok());

        let traceroute = result.unwrap();
        assert_eq!(
            traceroute.target_ip,
            IpAddr::V4("127.0.0.1".parse().unwrap())
        );
    }

    #[tokio::test]
    async fn test_async_traceroute_ipv6_error() {
        let config = TracerouteConfig::builder()
            .target("::1")
            .target_ip(IpAddr::V6("::1".parse().unwrap()))
            .build()
            .unwrap();

        let result = Traceroute::new(config).await;
        assert!(result.is_err());

        match result.unwrap_err() {
            TracerouteError::Ipv6NotSupported => {}
            _ => panic!("Expected IPv6 not supported error"),
        }
    }

    #[tokio::test]
    async fn test_async_traceroute_with_ip() {
        let config = TracerouteConfig::builder()
            .target("8.8.8.8")
            .target_ip(IpAddr::V4("8.8.8.8".parse().unwrap()))
            .build()
            .unwrap();

        let result = Traceroute::new(config).await;
        assert!(result.is_ok());

        let traceroute = result.unwrap();
        assert_eq!(traceroute.target_ip, IpAddr::V4("8.8.8.8".parse().unwrap()));
    }

    #[tokio::test]
    async fn test_trace_async_localhost() {
        // This may fail due to permissions, but should at least parse correctly
        let result = trace_async("127.0.0.1").await;

        // Either succeeds or fails with permissions
        match result {
            Ok(trace_result) => {
                assert_eq!(trace_result.target, "127.0.0.1");
            }
            Err(TracerouteError::InsufficientPermissions { .. }) => {
                // Expected on systems without proper permissions
            }
            Err(TracerouteError::SocketError(_)) => {
                // Also acceptable for socket creation failures
            }
            Err(e) => {
                panic!("Unexpected error: {:?}", e);
            }
        }
    }

    #[tokio::test]
    async fn test_trace_with_config_async() {
        let config = TracerouteConfig::builder()
            .target("127.0.0.1")
            .max_hops(3)
            .probe_timeout(Duration::from_millis(100))
            .build()
            .unwrap();

        let result = trace_with_config_async(config).await;

        // Either succeeds or fails with permissions
        match result {
            Ok(trace_result) => {
                assert_eq!(trace_result.target, "127.0.0.1");
                assert!(trace_result.hops.len() <= 3);
            }
            Err(TracerouteError::InsufficientPermissions { .. }) => {
                // Expected on systems without proper permissions
            }
            Err(TracerouteError::SocketError(_)) => {
                // Also acceptable for socket creation failures
            }
            Err(e) => {
                panic!("Unexpected error: {:?}", e);
            }
        }
    }

    #[tokio::test]
    async fn test_async_traceroute_hostname_resolution() {
        let config = TracerouteConfig::builder()
            .target("localhost")
            .build()
            .unwrap();

        let result = Traceroute::new(config).await;
        assert!(result.is_ok());

        let traceroute = result.unwrap();
        // localhost should resolve to 127.0.0.1
        assert_eq!(
            traceroute.target_ip,
            IpAddr::V4("127.0.0.1".parse().unwrap())
        );
    }

    #[tokio::test]
    async fn test_async_traceroute_invalid_hostname() {
        let config = TracerouteConfig::builder()
            .target("this.hostname.definitely.does.not.exist.invalid")
            .build()
            .unwrap();

        let result = Traceroute::new(config).await;
        assert!(result.is_err());

        match result.unwrap_err() {
            TracerouteError::ResolutionError(_) => {}
            _ => panic!("Expected resolution error"),
        }
    }

    #[tokio::test]
    async fn test_verbose_config_does_not_touch_environment() {
        let config = TracerouteConfig::builder()
            .target("127.0.0.1")
            .verbose(2)
            .max_hops(1) // Limit hops to make test faster
            .probe_timeout(Duration::from_millis(100))
            .build()
            .unwrap();
        assert_eq!(config.verbose, 2);

        let traceroute = Traceroute::new(config).await.unwrap();

        // Verbosity is threaded through explicitly; running a trace must not
        // mutate process-global environment state (which would race between
        // concurrent traces)
        let before = std::env::var("FTR_VERBOSE").ok();
        let _ = tokio::time::timeout(Duration::from_secs(5), traceroute.run()).await;
        assert_eq!(std::env::var("FTR_VERBOSE").ok(), before);
    }
}
