//! Async high-level traceroute API
//!
//! This module provides the async API for performing traceroute operations
//! with immediate response processing using Tokio.

use crate::socket::async_factory::create_async_probe_socket_with_options;
use crate::traceroute::fully_parallel_async_engine::FullyParallelAsyncEngine;
use crate::traceroute::{TracerouteConfig, TracerouteError, TracerouteResult};
use anyhow::Result;
use hickory_resolver::config::ResolverConfig;
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::TokioResolver;
use std::net::IpAddr;

/// Async traceroute API
#[derive(Debug)]
pub struct AsyncTraceroute {
    config: TracerouteConfig,
    target_ip: IpAddr,
}

impl AsyncTraceroute {
    /// Create a new async traceroute from configuration
    pub async fn new(mut config: TracerouteConfig) -> Result<Self, TracerouteError> {
        // Resolve target if needed
        let target_ip = if let Some(ip) = config.target_ip {
            ip
        } else {
            // Resolve hostname
            let resolver = TokioResolver::builder_with_config(
                ResolverConfig::cloudflare(),
                TokioConnectionProvider::default(),
            )
            .build();

            let response = resolver
                .lookup_ip(&config.target)
                .await
                .map_err(|e| TracerouteError::ResolutionError(e.to_string()))?;

            response
                .iter()
                .find(std::net::IpAddr::is_ipv4)
                .ok_or_else(|| {
                    TracerouteError::ResolutionError("No IPv4 address found".to_string())
                })?
        };

        // IPv6 check
        if target_ip.is_ipv6() {
            return Err(TracerouteError::Ipv6NotSupported);
        }

        config.target_ip = Some(target_ip);

        Ok(Self { config, target_ip })
    }

    /// Run the async traceroute
    pub async fn run(self) -> Result<TracerouteResult, TracerouteError> {
        // Create timing config from traceroute config
        let timing_config = crate::TimingConfig {
            receiver_poll_interval: self.config.send_interval,
            main_loop_poll_interval: self.config.send_interval,
            enrichment_wait_time: self.config.overall_timeout,
            socket_read_timeout: self.config.probe_timeout,
            udp_retry_delay: self.config.send_interval,
        };

        // Set verbose flag in environment for socket to pick up
        if self.config.verbose > 0 {
            std::env::set_var("FTR_VERBOSE", self.config.verbose.to_string());
        }

        // Create async socket with protocol preference
        let socket = create_async_probe_socket_with_options(
            self.target_ip,
            timing_config,
            self.config.protocol,
            self.config.socket_mode,
        )
        .await
        .map_err(|e| TracerouteError::SocketError(e.to_string()))?;

        // Create and run fully parallel async engine
        let engine = FullyParallelAsyncEngine::new(socket, self.config.clone(), self.target_ip)
            .await
            .map_err(|e| TracerouteError::SocketError(e.to_string()))?;
        let result = engine
            .run()
            .await
            .map_err(|e| TracerouteError::SocketError(e.to_string()))?;

        // The fully parallel engine handles enrichment internally, so we can just return
        Ok(result)
    }
}

/// Run an async traceroute with the given configuration
pub async fn trace_async(target: &str) -> Result<TracerouteResult, TracerouteError> {
    let config = TracerouteConfig::builder()
        .target(target)
        .build()
        .map_err(TracerouteError::ConfigError)?;
    trace_with_config_async(config).await
}

/// Run an async traceroute with a custom configuration
pub async fn trace_with_config_async(
    config: TracerouteConfig,
) -> Result<TracerouteResult, TracerouteError> {
    let traceroute = AsyncTraceroute::new(config).await?;
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

        let result = AsyncTraceroute::new(config).await;
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

        let result = AsyncTraceroute::new(config).await;
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

        let result = AsyncTraceroute::new(config).await;
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

        let result = AsyncTraceroute::new(config).await;
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

        let result = AsyncTraceroute::new(config).await;
        assert!(result.is_err());

        match result.unwrap_err() {
            TracerouteError::ResolutionError(_) => {}
            _ => panic!("Expected resolution error"),
        }
    }

    #[tokio::test]
    async fn test_verbose_environment_setting() {
        let config = TracerouteConfig::builder()
            .target("127.0.0.1")
            .verbose(2)
            .max_hops(1) // Limit hops to make test faster
            .probe_timeout(Duration::from_millis(100))
            .build()
            .unwrap();

        let traceroute = AsyncTraceroute::new(config).await.unwrap();

        // Store original value
        let original = std::env::var("FTR_VERBOSE").ok();

        // This will set the environment variable (with timeout)
        let _ = tokio::time::timeout(Duration::from_secs(5), traceroute.run()).await;

        // Check it was set
        assert_eq!(std::env::var("FTR_VERBOSE").ok(), Some("2".to_string()));

        // Restore original
        match original {
            Some(val) => std::env::set_var("FTR_VERBOSE", val),
            None => std::env::remove_var("FTR_VERBOSE"),
        }
    }
}
