//! Fully parallel async traceroute engine
//!
//! This implementation maximizes parallelism by:
//! 1. Starting ISP detection (STUN) immediately on launch
//! 2. Sending all probes in parallel
//! 3. Starting ASN/rDNS enrichment immediately as each response arrives
//! 4. Using caches to avoid duplicate lookups

use crate::caches::Caches;
use crate::enrichment::AsyncEnrichmentService;
use crate::probe::{ProbeInfo, ProbeResponse};
use crate::public_ip::{detect_isp_from_ip, detect_isp_with_default_resolver};
use crate::socket::async_trait::AsyncProbeSocket;
use crate::socket::{ProbeProtocol, SocketMode};
use crate::trace_time;
use crate::traceroute::{AsnInfo, ClassifiedHopInfo, SegmentType, TracerouteResult};
use anyhow::Result;
use futures::stream::{FuturesUnordered, StreamExt};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tokio::time::{sleep, timeout};

/// Enrichment result for an address
#[derive(Clone)]
struct EnrichmentResult {
    hostname: Option<String>,
    asn_info: Option<AsnInfo>,
}

/// Fully parallel async traceroute engine
pub struct FullyParallelAsyncEngine {
    socket: Arc<Box<dyn AsyncProbeSocket>>,
    config: crate::TracerouteConfig,
    target: IpAddr,
    enrichment_service: Arc<AsyncEnrichmentService>,
    enrichment_cache: Arc<Mutex<HashMap<IpAddr, EnrichmentResult>>>,
    #[allow(dead_code)] // Will be used in Phase 3
    caches: Option<Caches>,
}

impl FullyParallelAsyncEngine {
    /// Create a new fully parallel async traceroute engine with injected caches
    pub async fn new_with_caches(
        socket: Box<dyn AsyncProbeSocket>,
        config: crate::TracerouteConfig,
        target: IpAddr,
        caches: Caches,
    ) -> Result<Self> {
        // Create enrichment service upfront
        let enrichment_service = Arc::new(AsyncEnrichmentService::new().await?);

        Ok(Self {
            socket: Arc::new(socket),
            config,
            target,
            enrichment_service,
            enrichment_cache: Arc::new(Mutex::new(HashMap::new())),
            caches: Some(caches),
        })
    }

    /// Create a new fully parallel async traceroute engine (uses global caches)
    pub async fn new(
        socket: Box<dyn AsyncProbeSocket>,
        config: crate::TracerouteConfig,
        target: IpAddr,
    ) -> Result<Self> {
        // Create enrichment service upfront
        let enrichment_service = Arc::new(AsyncEnrichmentService::new().await?);

        Ok(Self {
            socket: Arc::new(socket),
            config,
            target,
            enrichment_service,
            enrichment_cache: Arc::new(Mutex::new(HashMap::new())),
            caches: None,
        })
    }

    /// Run the fully parallel async traceroute
    pub async fn run(&self) -> Result<TracerouteResult> {
        let start_time = Instant::now();
        trace_time!(
            self.config.verbose,
            "Starting fully parallel async traceroute to {}",
            self.target
        );

        // 1. Start ISP detection immediately (if enabled)
        let isp_future = if self.config.enable_asn_lookup {
            if let Some(public_ip) = self.config.public_ip {
                // Use provided public IP
                trace_time!(
                    self.config.verbose,
                    "Using provided public IP: {}",
                    public_ip
                );
                let verbose = self.config.verbose;
                Some(tokio::spawn(async move {
                    let isp_start = Instant::now();
                    let result = detect_isp_from_ip(public_ip, None).await;
                    trace_time!(
                        verbose,
                        "ISP detection from provided IP completed in {:?}",
                        isp_start.elapsed()
                    );
                    result
                }))
            } else {
                // Use STUN detection
                trace_time!(
                    self.config.verbose,
                    "Starting ISP detection (STUN) in parallel"
                );
                let verbose = self.config.verbose;
                Some(tokio::spawn(async move {
                    let isp_start = Instant::now();
                    let result = detect_isp_with_default_resolver().await;
                    trace_time!(
                        verbose,
                        "ISP detection completed in {:?}",
                        isp_start.elapsed()
                    );
                    result
                }))
            }
        } else {
            None
        };

        // 2. Create futures for all probes with immediate enrichment
        let mut probe_futures = FuturesUnordered::new();
        let mut sequence = 1u16;

        trace_time!(
            self.config.verbose,
            "Creating probe futures with immediate enrichment"
        );
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
                let enrichment_service = Arc::clone(&self.enrichment_service);
                let enrichment_cache = Arc::clone(&self.enrichment_cache);
                let enable_asn = self.config.enable_asn_lookup;
                let enable_rdns = self.config.enable_rdns;

                // Create future that sends probe AND enriches response immediately
                let probe_future = async move {
                    trace_time!(
                        verbose,
                        "Sending probe seq={} ttl={}",
                        probe.sequence,
                        probe.ttl
                    );

                    match socket.send_probe_and_recv(target, probe).await {
                        Ok(response) => {
                            trace_time!(
                                verbose,
                                "Received response seq={} ttl={} from={} rtt={:?}",
                                response.sequence,
                                response.ttl,
                                response.from_addr,
                                response.rtt
                            );

                            // Start enrichment immediately if not cached
                            if enable_asn || enable_rdns {
                                let cache = enrichment_cache.lock().await;
                                if !cache.contains_key(&response.from_addr) {
                                    drop(cache); // Release lock before enrichment

                                    trace_time!(
                                        verbose,
                                        "Starting immediate enrichment for {}",
                                        response.from_addr
                                    );
                                    let enrich_start = Instant::now();

                                    // Enrich this single address
                                    let enrichment_results = enrichment_service
                                        .enrich_addresses(vec![response.from_addr])
                                        .await;

                                    if let Some(enrichment) =
                                        enrichment_results.get(&response.from_addr)
                                    {
                                        trace_time!(
                                            verbose,
                                            "Enrichment for {} completed in {:?}",
                                            response.from_addr,
                                            enrich_start.elapsed()
                                        );

                                        // Cache the result
                                        let mut cache = enrichment_cache.lock().await;
                                        cache.insert(
                                            response.from_addr,
                                            EnrichmentResult {
                                                hostname: enrichment.hostname.clone(),
                                                asn_info: enrichment.asn_info.clone(),
                                            },
                                        );
                                    }
                                }
                            }

                            Some(response)
                        }
                        Err(_) => None,
                    }
                };

                probe_futures.push(probe_future);
            }
        }

        trace_time!(
            self.config.verbose,
            "Started {} probe futures",
            sequence - 1
        );

        // 3. Collect responses as they arrive
        let mut responses: Vec<ProbeResponse> = Vec::new();
        let mut ttl_responses: HashMap<u8, usize> = HashMap::new();
        let mut destination_ttl: Option<u8> = None;

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

                    // Check if we can exit early
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
                                "Early exit - all TTLs up to destination responded"
                            );
                            // Wait briefly for late responses
                            sleep(Duration::from_millis(25)).await;

                            // Collect any remaining
                            while let Ok(Some(response)) =
                                timeout(Duration::from_millis(10), probe_futures.next()).await
                            {
                                if let Some(resp) = response {
                                    responses.push(resp);
                                }
                            }
                            break;
                        }
                    }
                }
            }
        };

        // Execute with overall timeout
        let _ = timeout(self.config.overall_timeout, collection_future).await;
        trace_time!(
            self.config.verbose,
            "Response collection completed in {:?}",
            collection_start.elapsed()
        );

        // 4. Build result with cached enrichment data
        let elapsed = start_time.elapsed();
        self.build_result(responses, elapsed, isp_future).await
    }

    /// Build the final traceroute result with enriched data
    async fn build_result(
        &self,
        responses: Vec<ProbeResponse>,
        elapsed: Duration,
        isp_future: Option<
            tokio::task::JoinHandle<
                Result<crate::traceroute::IspInfo, crate::public_ip::PublicIpError>,
            >,
        >,
    ) -> Result<TracerouteResult> {
        let mut hops: HashMap<u8, Vec<ProbeResponse>> = HashMap::new();

        // Group responses by TTL
        for response in responses {
            hops.entry(response.ttl).or_default().push(response);
        }

        // Check if destination was reached
        let destination_reached = hops
            .values()
            .any(|ttl_responses| ttl_responses.iter().any(|r| r.is_destination));

        let destination_ttl = hops
            .values()
            .flat_map(|ttl_responses| ttl_responses.iter())
            .filter(|r| r.is_destination)
            .map(|r| r.ttl)
            .min()
            .unwrap_or(self.config.max_hops);

        // Wait for ISP detection to complete
        let isp_info = if let Some(future) = isp_future {
            trace_time!(self.config.verbose, "Waiting for ISP detection to complete");
            match future.await {
                Ok(Ok(isp)) => Some(isp),
                Ok(Err(e)) => {
                    trace_time!(self.config.verbose, "ISP detection failed: {}", e);
                    None
                }
                Err(e) => {
                    trace_time!(self.config.verbose, "ISP detection task failed: {}", e);
                    None
                }
            }
        } else {
            None
        };

        // Get ISP ASN for segment classification
        let isp_asn = isp_info.as_ref().map(|isp| isp.asn);

        // Build classified hops with enrichment data
        let enrichment_cache = self.enrichment_cache.lock().await;
        let mut hop_infos: Vec<ClassifiedHopInfo> = Vec::new();
        let mut in_isp_segment = false;

        let display_max_ttl = if destination_reached {
            destination_ttl
        } else {
            self.config.max_hops
        };

        for ttl in self.config.start_ttl..=display_max_ttl {
            if let Some(ttl_responses) = hops.get(&ttl) {
                if !ttl_responses.is_empty() {
                    // Get unique addresses
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

                        // Calculate average RTT
                        let rtt = if !addr_responses.is_empty() {
                            let total_rtt: Duration = addr_responses.iter().map(|r| r.rtt).sum();
                            Some(total_rtt / addr_responses.len() as u32)
                        } else {
                            None
                        };

                        // Get cached enrichment data
                        let enrichment = enrichment_cache.get(&addr);
                        let hostname = enrichment.and_then(|e| e.hostname.clone());
                        let asn_info = enrichment.and_then(|e| e.asn_info.clone());

                        // Classify segment
                        let segment = if let IpAddr::V4(ipv4) = addr {
                            if crate::traceroute::is_internal_ip(&ipv4) {
                                SegmentType::Lan
                            } else if crate::traceroute::is_cgnat(&ipv4) {
                                in_isp_segment = true;
                                SegmentType::Isp
                            } else if let Some(isp) = isp_asn {
                                if let Some(ref asn) = asn_info {
                                    if asn.asn == isp {
                                        in_isp_segment = true;
                                        SegmentType::Isp
                                    } else {
                                        SegmentType::Beyond
                                    }
                                } else if in_isp_segment {
                                    SegmentType::Isp
                                } else {
                                    SegmentType::Unknown
                                }
                            } else {
                                SegmentType::Unknown
                            }
                        } else {
                            SegmentType::Unknown
                        };

                        hop_infos.push(ClassifiedHopInfo {
                            ttl,
                            segment,
                            hostname,
                            addr: Some(addr),
                            asn_info,
                            rtt,
                        });
                    }

                    // Add timeout responses
                    let timeout_count = ttl_responses.iter().filter(|r| r.is_timeout).count();
                    for _ in 0..timeout_count {
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
            } else {
                // Add blank hop
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

        // Determine protocol and socket mode
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

        trace_time!(
            self.config.verbose,
            "Total fully parallel async traceroute completed in {:?}",
            elapsed
        );

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
