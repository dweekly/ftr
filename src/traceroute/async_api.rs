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

            response.iter().find(|ip| ip.is_ipv4()).ok_or_else(|| {
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
        .map_err(|e| TracerouteError::ConfigError(e))?;
    trace_with_config_async(config).await
}

/// Run an async traceroute with a custom configuration
pub async fn trace_with_config_async(
    config: TracerouteConfig,
) -> Result<TracerouteResult, TracerouteError> {
    let traceroute = AsyncTraceroute::new(config).await?;
    traceroute.run().await
}
