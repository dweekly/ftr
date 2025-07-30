//! Async high-level traceroute API
//!
//! This module provides the async API for performing traceroute operations
//! with immediate response processing using Tokio.

#[cfg(feature = "async")]
use crate::enrichment::AsyncEnrichmentService;
use crate::socket::async_factory::create_async_probe_socket;
use crate::traceroute::async_engine::AsyncTracerouteEngine;
use crate::traceroute::{SegmentType, TracerouteConfig, TracerouteError, TracerouteResult};
use anyhow::Result;
use hickory_resolver::config::ResolverConfig;
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::TokioResolver;
use std::net::IpAddr;
use std::sync::Arc;

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

        // Create async socket
        let socket = create_async_probe_socket(self.target_ip, timing_config)
            .await
            .map_err(|e| TracerouteError::SocketError(e.to_string()))?;

        // Create and run async engine
        let engine = AsyncTracerouteEngine::new(socket, self.config.clone(), self.target_ip);
        let mut result = engine
            .run()
            .await
            .map_err(|e| TracerouteError::SocketError(e.to_string()))?;

        // Perform enrichment if enabled
        if self.config.enable_asn_lookup || self.config.enable_rdns {
            let enrichment_service = Arc::new(
                AsyncEnrichmentService::new()
                    .await
                    .map_err(|e| TracerouteError::SocketError(e.to_string()))?,
            );

            // Collect unique addresses for enrichment
            let addresses: Vec<IpAddr> = result.hops.iter().filter_map(|hop| hop.addr).collect();

            // Enrich addresses
            let enrichment_results = enrichment_service.enrich_addresses(addresses).await;

            // Get ISP ASN from public IP info
            let isp_asn = result.isp_info.as_ref().map(|isp| isp.asn);
            let mut in_isp_segment = false;

            // Apply enrichment results to hops and fix segment classification
            for hop in &mut result.hops {
                if let Some(addr) = hop.addr {
                    if let Some(enrichment) = enrichment_results.get(&addr) {
                        if self.config.enable_rdns {
                            hop.hostname = enrichment.hostname.clone();
                        }
                        if self.config.enable_asn_lookup {
                            hop.asn_info = enrichment.asn_info.clone();
                        }
                    }

                    // Now properly classify the segment with enrichment data
                    if let IpAddr::V4(ipv4) = addr {
                        if crate::traceroute::is_internal_ip(&ipv4) {
                            hop.segment = SegmentType::Lan;
                        } else if crate::traceroute::is_cgnat(&ipv4) {
                            in_isp_segment = true;
                            hop.segment = SegmentType::Isp;
                        } else if let Some(isp) = isp_asn {
                            if let Some(ref asn_info) = hop.asn_info {
                                if asn_info.asn == isp {
                                    in_isp_segment = true;
                                    hop.segment = SegmentType::Isp;
                                } else {
                                    hop.segment = SegmentType::Beyond;
                                }
                            } else if in_isp_segment {
                                hop.segment = SegmentType::Isp;
                            } else {
                                hop.segment = SegmentType::Unknown;
                            }
                        } else {
                            hop.segment = SegmentType::Unknown;
                        }
                    }
                }
            }
        }

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
