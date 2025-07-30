//! Async traceroute engine
//!
//! This module implements the async traceroute engine that uses
//! Tokio for immediate response processing.

use crate::probe::{ProbeInfo, ProbeResponse};
use crate::socket::async_trait::AsyncProbeSocket;
use crate::socket::{ProbeProtocol, SocketMode};
use crate::traceroute::{ClassifiedHopInfo, TracerouteResult, SegmentType};
use anyhow::Result;
use futures::stream::{FuturesUnordered, StreamExt};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::timeout;

/// Async traceroute engine
pub struct AsyncTracerouteEngine {
    socket: Arc<Box<dyn AsyncProbeSocket>>,
    config: crate::TracerouteConfig,
    target: IpAddr,
}

impl AsyncTracerouteEngine {
    /// Create a new async traceroute engine
    pub fn new(
        socket: Box<dyn AsyncProbeSocket>,
        config: crate::TracerouteConfig,
        target: IpAddr,
    ) -> Self {
        Self {
            socket: Arc::new(socket),
            config,
            target,
        }
    }

    /// Run the async traceroute
    pub async fn run(&self) -> Result<TracerouteResult> {
        let start_time = Instant::now();
        let mut probe_futures = FuturesUnordered::new();
        let mut responses: Vec<ProbeResponse> = Vec::new();
        let mut sequence = 1u16;

        // Send all probes concurrently
        for ttl in self.config.start_ttl..=self.config.max_hops {
            for _query in 0..self.config.queries_per_hop {
                let probe = ProbeInfo {
                    sequence,
                    ttl,
                    sent_at: Instant::now(),
                };
                sequence += 1;

                let socket = Arc::clone(&self.socket);
                let target = self.target;
                let timeout_duration = self.config.probe_timeout;

                // Create future for this probe with timeout
                let probe_future = async move {
                    match timeout(timeout_duration, socket.send_probe_and_recv(target, probe)).await {
                        Ok(Ok(response)) => Some(response),
                        Ok(Err(_)) | Err(_) => {
                            // Timeout or error - create timeout response
                            Some(ProbeResponse {
                                from_addr: target,
                                sequence: probe.sequence,
                                ttl: probe.ttl,
                                rtt: timeout_duration,
                                received_at: Instant::now(),
                                is_destination: false,
                                is_timeout: true,
                            })
                        }
                    }
                };

                probe_futures.push(probe_future);
            }
        }

        // Set overall timeout for all probes
        let overall_timeout = timeout(
            Duration::from_secs(self.config.max_hops as u64 * 2),
            async {
                // Collect responses as they arrive - IMMEDIATELY
                while let Some(response) = probe_futures.next().await {
                    if let Some(resp) = response {
                        let is_destination = resp.is_destination;
                        responses.push(resp);

                        // Check if we should stop early
                        if is_destination && self.should_stop(&responses) {
                            break;
                        }
                    }
                }
            },
        );

        // Execute with timeout
        let _ = overall_timeout.await;

        // Build the result
        let elapsed = start_time.elapsed();
        self.build_result(responses, elapsed)
    }

    /// Check if we should stop sending probes
    fn should_stop(&self, responses: &[ProbeResponse]) -> bool {
        // Stop if we've reached the destination with enough responses
        let destination_responses = responses
            .iter()
            .filter(|r| r.is_destination)
            .count();

        destination_responses >= self.config.queries_per_hop as usize
    }

    /// Build the final traceroute result
    fn build_result(&self, responses: Vec<ProbeResponse>, elapsed: Duration) -> Result<TracerouteResult> {
        let mut hops: HashMap<u8, Vec<ProbeResponse>> = HashMap::new();

        // Check if destination was reached before consuming responses
        let destination_reached = responses.iter().any(|r| r.is_destination);

        // Group responses by TTL
        for response in responses {
            hops.entry(response.ttl).or_default().push(response);
        }

        // Convert to ClassifiedHopInfo
        let mut hop_infos: Vec<ClassifiedHopInfo> = Vec::new();
        
        for ttl in self.config.start_ttl..=self.config.max_hops {
            if let Some(ttl_responses) = hops.get(&ttl) {
                if !ttl_responses.is_empty() {
                    // Get unique addresses for this hop
                    let mut unique_addrs: Vec<IpAddr> = ttl_responses
                        .iter()
                        .filter(|r| !r.is_timeout)
                        .map(|r| r.from_addr)
                        .collect();
                    unique_addrs.sort();
                    unique_addrs.dedup();

                    for addr in unique_addrs {
                        let addr_responses: Vec<&ProbeResponse> = ttl_responses
                            .iter()
                            .filter(|r| r.from_addr == addr)
                            .collect();

                        // Calculate average RTT for this hop
                        let rtt = if !addr_responses.is_empty() {
                            let total_rtt: Duration = addr_responses
                                .iter()
                                .map(|r| r.rtt)
                                .sum();
                            Some(total_rtt / addr_responses.len() as u32)
                        } else {
                            None
                        };

                        let hop_info = ClassifiedHopInfo {
                            ttl,
                            segment: classify_segment(&addr), // Simple classification for now
                            hostname: None, // Will be enriched later
                            addr: Some(addr),
                            asn_info: None, // Will be enriched later
                            rtt,
                        };

                        hop_infos.push(hop_info);
                    }

                    // Add timeout responses if any
                    let timeout_count = ttl_responses.iter().filter(|r| r.is_timeout).count();
                    if timeout_count > 0 {
                        let timeout_hop = ClassifiedHopInfo {
                            ttl,
                            segment: SegmentType::Unknown,
                            hostname: None,
                            addr: None,
                            asn_info: None,
                            rtt: None,
                        };

                        hop_infos.push(timeout_hop);
                    }
                }
            }
        }

        // Sort by TTL
        hop_infos.sort_by_key(|h| h.ttl);

        // Determine protocol and socket mode used
        let (protocol_used, socket_mode_used) = match self.socket.mode() {
            crate::socket::async_trait::ProbeMode::DgramIcmp => {
                (ProbeProtocol::Icmp, SocketMode::Dgram)
            }
            crate::socket::async_trait::ProbeMode::WindowsIcmp => {
                (ProbeProtocol::Icmp, SocketMode::Raw)
            }
            crate::socket::async_trait::ProbeMode::UdpWithRecverr => {
                (ProbeProtocol::Udp, SocketMode::Dgram)
            }
            crate::socket::async_trait::ProbeMode::RawIcmp => {
                (ProbeProtocol::Icmp, SocketMode::Raw)
            }
        };

        Ok(TracerouteResult {
            target: self.config.target.clone(),
            target_ip: self.target,
            hops: hop_infos,
            isp_info: None, // Will be enriched later
            protocol_used,
            socket_mode_used,
            destination_reached,
            total_duration: elapsed,
        })
    }
}

/// Simple segment classification based on IP address
fn classify_segment(addr: &IpAddr) -> SegmentType {
    match addr {
        IpAddr::V4(ipv4) => {
            if crate::traceroute::is_internal_ip(ipv4) {
                SegmentType::Lan
            } else if crate::traceroute::is_cgnat(ipv4) {
                SegmentType::Isp
            } else {
                SegmentType::Beyond
            }
        }
        IpAddr::V6(_) => SegmentType::Unknown,
    }
}