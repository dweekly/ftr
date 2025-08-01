//! Async traceroute engine
//!
//! This module implements the async traceroute engine that uses
//! Tokio for immediate response processing.

use crate::probe::{ProbeInfo, ProbeResponse};
use crate::socket::async_trait::AsyncProbeSocket;
use crate::socket::{ProbeProtocol, SocketMode};
use crate::trace_time;
use crate::traceroute::{ClassifiedHopInfo, SegmentType, TracerouteResult};
use anyhow::Result;
use futures::stream::{FuturesUnordered, StreamExt};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::{sleep, timeout};

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
        trace_time!(
            self.config.verbose,
            "Starting async traceroute to {}",
            self.target
        );

        let mut probe_futures = FuturesUnordered::new();
        let mut responses: Vec<ProbeResponse> = Vec::new();
        let mut sequence = 1u16;

        // Track which TTLs have received at least one response
        let mut ttl_responses: HashMap<u8, usize> = HashMap::new();
        let mut destination_ttl: Option<u8> = None;

        // Send all probes concurrently
        let probe_send_start = Instant::now();
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
                let verbose = self.config.verbose;

                // Create future for this probe - the socket implementation handles timeouts
                let probe_future = async move {
                    trace_time!(
                        verbose,
                        "Sending probe seq={} ttl={}",
                        probe.sequence,
                        probe.ttl
                    );
                    let result = socket.send_probe_and_recv(target, probe).await.ok();
                    if let Some(ref resp) = result {
                        trace_time!(
                            verbose,
                            "Received response seq={} ttl={} from={} rtt={:?}",
                            resp.sequence,
                            resp.ttl,
                            resp.from_addr,
                            resp.rtt
                        );
                    }
                    result
                };

                probe_futures.push(probe_future);
            }
        }
        trace_time!(
            self.config.verbose,
            "Finished creating {} probe futures in {:?}",
            sequence - 1,
            probe_send_start.elapsed()
        );

        // Collect responses
        let collection_start = Instant::now();
        trace_time!(self.config.verbose, "Starting response collection");
        let collection_future = async {
            while let Some(response) = probe_futures.next().await {
                if let Some(resp) = response {
                    let ttl = resp.ttl;
                    let is_destination = resp.is_destination;

                    // Track responses per TTL
                    *ttl_responses.entry(ttl).or_insert(0) += 1;

                    // Update destination TTL if we found it
                    if is_destination && destination_ttl.is_none() {
                        destination_ttl = Some(ttl);
                    }

                    responses.push(resp);

                    // Check if we can exit early:
                    // We need at least one response from each TTL up to the destination
                    if let Some(dest_ttl) = destination_ttl {
                        let mut can_exit = true;
                        for check_ttl in self.config.start_ttl..=dest_ttl {
                            if ttl_responses.get(&check_ttl).copied().unwrap_or(0) == 0 {
                                can_exit = false;
                                break;
                            }
                        }
                        if can_exit {
                            trace_time!(
                                self.config.verbose,
                                "Early exit condition met - all TTLs up to destination responded"
                            );
                            // We have responses from all TTLs up to destination
                            // But we still need to wait a bit for any in-flight responses
                            // from intermediate hops that might arrive late
                            let late_wait_start = Instant::now();
                            sleep(Duration::from_millis(25)).await;
                            trace_time!(self.config.verbose, "Waited 25ms for late responses");

                            // Collect any remaining responses that arrived
                            let mut late_count = 0;
                            while let Ok(Some(response)) =
                                timeout(Duration::from_millis(10), probe_futures.next()).await
                            {
                                if let Some(resp) = response {
                                    responses.push(resp);
                                    late_count += 1;
                                }
                            }
                            trace_time!(
                                self.config.verbose,
                                "Collected {} late responses in {:?}",
                                late_count,
                                late_wait_start.elapsed()
                            );
                            break;
                        }
                    }
                }
            }
        };

        // Execute with overall timeout
        let timeout_result = timeout(self.config.overall_timeout, collection_future).await;
        let collection_elapsed = collection_start.elapsed();
        trace_time!(
            self.config.verbose,
            "Response collection completed in {:?}, timeout={}",
            collection_elapsed,
            timeout_result.is_err()
        );
        trace_time!(
            self.config.verbose,
            "Total responses collected: {}",
            responses.len()
        );

        // Build the result
        let build_start = Instant::now();
        let elapsed = start_time.elapsed();
        let result = self.build_result(responses, elapsed).await;
        trace_time!(
            self.config.verbose,
            "Result building completed in {:?}",
            build_start.elapsed()
        );
        trace_time!(
            self.config.verbose,
            "Total async traceroute completed in {:?}",
            elapsed
        );
        result
    }

    /// Build the final traceroute result
    async fn build_result(
        &self,
        responses: Vec<ProbeResponse>,
        elapsed: Duration,
    ) -> Result<TracerouteResult> {
        let mut hops: HashMap<u8, Vec<ProbeResponse>> = HashMap::new();

        // Check if destination was reached and find destination TTL
        let destination_reached = responses.iter().any(|r| r.is_destination);
        let destination_ttl = responses
            .iter()
            .filter(|r| r.is_destination)
            .map(|r| r.ttl)
            .min()
            .unwrap_or(self.config.max_hops);

        // Group responses by TTL
        for response in responses {
            hops.entry(response.ttl).or_default().push(response);
        }

        // Determine the actual max TTL to process (up to destination or max_hops)
        let display_max_ttl = if destination_reached {
            destination_ttl
        } else {
            self.config.max_hops
        };

        // Convert to ClassifiedHopInfo
        let mut hop_infos: Vec<ClassifiedHopInfo> = Vec::new();

        for ttl in self.config.start_ttl..=display_max_ttl {
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
                            let total_rtt: Duration = addr_responses.iter().map(|r| r.rtt).sum();
                            Some(total_rtt / addr_responses.len() as u32)
                        } else {
                            None
                        };

                        // Note: Without enrichment here, we can't properly classify segments
                        // This will be fixed when enrichment is moved into the engine
                        let hop_info = ClassifiedHopInfo {
                            ttl,
                            segment: SegmentType::Unknown, // Will be properly classified with enrichment
                            hostname: None,                // Will be enriched later
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
            } else {
                // Add blank hop for missing TTL
                hop_infos.push(ClassifiedHopInfo {
                    ttl,
                    segment: SegmentType::Unknown,
                    hostname: None,
                    addr: None,
                    asn_info: None,
                    rtt: None,
                });
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

        // Try to extract ISP info from the traceroute path itself (fast path)
        let isp_info = if self.config.enable_asn_lookup {
            // Note: We'll do this after enrichment in async_api.rs where we have enriched hops
            None
        } else {
            None
        };

        Ok(TracerouteResult {
            target: self.config.target.clone(),
            target_ip: self.target,
            hops: hop_infos,
            isp_info,
            protocol_used,
            socket_mode_used,
            destination_reached,
            total_duration: elapsed,
        })
    }
}
