//! Core traceroute engine implementation

#![allow(clippy::single_match)]
#![allow(clippy::nonminimal_bool)]

use crate::asn::lookup_asn;
use crate::dns::reverse_dns_lookup;
use crate::public_ip::detect_isp_with_default_resolver;
use crate::socket::{ProbeInfo, ProbeResponse, ProbeSocket, ResponseType};
use crate::traceroute::{
    ClassifiedHopInfo, RawHopInfo, SegmentType, TracerouteConfig, TracerouteProgress,
    TracerouteResult,
};
use hickory_resolver::config::ResolverConfig;
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::TokioResolver;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot};
// use crate::debug_print;

/// Error type for traceroute operations
///
/// Represents various failures that can occur during traceroute execution.
///
/// # Examples
///
/// ```
/// # use ftr::TracerouteError;
/// fn handle_error(err: TracerouteError) {
///     match err {
///         TracerouteError::InsufficientPermissions { required, suggestion } => {
///             eprintln!("Insufficient permissions: {}", required);
///             eprintln!("Try: {}", suggestion);
///         }
///         TracerouteError::ResolutionError(msg) => {
///             eprintln!("DNS resolution failed: {}", msg);
///         }
///         _ => eprintln!("Traceroute failed: {}", err),
///     }
/// }
/// ```
#[derive(Debug, thiserror::Error)]
pub enum TracerouteError {
    /// Socket creation failed due to insufficient permissions
    ///
    /// This error provides structured information about what permissions
    /// are needed and how to obtain them.
    #[error("Insufficient permissions: {required}")]
    InsufficientPermissions {
        /// Description of required permissions (e.g., "root or CAP_NET_RAW")
        required: String,
        /// Suggested remedy (e.g., "Run with sudo or use --udp mode")
        suggestion: String,
    },

    /// Socket creation failed for other reasons
    #[error("Failed to create socket: {0}")]
    SocketError(String),

    /// DNS resolution failed
    ///
    /// The target hostname could not be resolved to an IP address.
    #[error("Failed to resolve host: {0}")]
    ResolutionError(String),

    /// Probe sending failed
    ///
    /// Failed to send a probe packet, possibly due to network issues.
    #[error("Failed to send probe: {0}")]
    ProbeSendError(String),

    /// Configuration error
    ///
    /// The provided configuration is invalid or incompatible.
    #[error("Configuration error: {0}")]
    ConfigError(String),

    /// Feature not yet implemented
    ///
    /// The requested feature (TCP, IPv6) is not yet implemented.
    #[error("{feature} is not yet implemented")]
    NotImplemented {
        /// Feature name (e.g., "TCP traceroute", "IPv6 support")
        feature: String,
    },

    /// Target is IPv6 (not yet supported)
    ///
    /// IPv6 targets are not yet fully supported in this version.
    #[error("IPv6 targets are not yet supported")]
    Ipv6NotSupported,
}

/// Enrichment result for a hop
#[derive(Clone)]
struct EnrichmentResult {
    ip: IpAddr,
    hostname: Option<String>,
    asn_info: Option<crate::traceroute::AsnInfo>,
}

/// Events that can occur during traceroute
#[derive(Debug)]
#[allow(dead_code)]
enum TracerouteEvent {
    /// A probe response was received
    ResponseReceived(ProbeResponse),
    /// A probe timed out
    ProbeTimeout { sequence: u16 },
    /// Destination was reached
    DestinationReached { ttl: u8 },
    /// All probes completed (either responded or timed out)
    AllProbesComplete,
    /// Windows event signaled (probe completed but may not have response)
    #[cfg(target_os = "windows")]
    WindowsEventSignaled { sequence: u16 },
}

/// Traceroute engine
pub struct TracerouteEngine {
    config: TracerouteConfig,
    socket: Arc<Box<dyn ProbeSocket>>,
    results: Arc<Mutex<HashMap<u8, RawHopInfo>>>,
    active_probes: Arc<Mutex<HashMap<u16, ProbeInfo>>>,
    destination_reached: Arc<Mutex<bool>>,
    destination_ttl: Arc<Mutex<Option<u8>>>,
    enrichment_results: Arc<Mutex<HashMap<IpAddr, EnrichmentResult>>>,
    completed_probes: Arc<Mutex<u32>>,
}

impl TracerouteEngine {
    /// Create a new traceroute engine
    pub fn new(
        config: TracerouteConfig,
        socket: Box<dyn ProbeSocket>,
    ) -> Result<Self, TracerouteError> {
        // Validate config
        config.validate().map_err(TracerouteError::ConfigError)?;

        Ok(Self {
            config,
            socket: Arc::new(socket),
            results: Arc::new(Mutex::new(HashMap::new())),
            active_probes: Arc::new(Mutex::new(HashMap::new())),
            destination_reached: Arc::new(Mutex::new(false)),
            destination_ttl: Arc::new(Mutex::new(None)),
            enrichment_results: Arc::new(Mutex::new(HashMap::new())),
            completed_probes: Arc::new(Mutex::new(0)),
        })
    }

    /// Run the traceroute
    pub async fn run(self) -> Result<TracerouteResult, TracerouteError> {
        let start_time = Instant::now();

        // Get target IP
        let target_ip = match self.config.target_ip {
            Some(ip) => ip,
            None => {
                // Resolve hostname
                resolve_host(&self.config.target).await?
            }
        };

        // Only support IPv4 for now
        let target_ipv4 = match target_ip {
            IpAddr::V4(ipv4) => ipv4,
            IpAddr::V6(_) => return Err(TracerouteError::Ipv6NotSupported),
        };

        // Start ISP detection in parallel if needed
        let enrichment_enabled = self.config.enable_asn_lookup || self.config.enable_rdns;
        let public_ip_future = if enrichment_enabled && self.config.public_ip.is_none() {
            let enrichment_results = Arc::clone(&self.enrichment_results);
            let enable_asn = self.config.enable_asn_lookup;
            let enable_rdns = self.config.enable_rdns;
            Some(tokio::spawn(async move {
                use crate::public_ip::{get_public_ip, PublicIpProvider};

                // Get public IP first
                if let Ok(public_ip) = get_public_ip(PublicIpProvider::default()).await {
                    // Immediately start ASN and rDNS lookups in parallel
                    let resolver = Arc::new(crate::dns::create_default_resolver());

                    let asn_future = async {
                        if enable_asn {
                            if let IpAddr::V4(ipv4) = public_ip {
                                lookup_asn(ipv4, Some(Arc::clone(&resolver))).await.ok()
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    };

                    let rdns_future = async {
                        if enable_rdns {
                            reverse_dns_lookup(public_ip, Some(Arc::clone(&resolver)))
                                .await
                                .ok()
                        } else {
                            None
                        }
                    };

                    // Run both in parallel
                    let (asn_info, hostname) = tokio::join!(asn_future, rdns_future);

                    // Store the enrichment result
                    enrichment_results.lock().expect("mutex poisoned").insert(
                        public_ip,
                        EnrichmentResult {
                            ip: public_ip,
                            hostname: hostname.clone(),
                            asn_info: asn_info.clone(),
                        },
                    );

                    Some((public_ip, asn_info, hostname))
                } else {
                    None
                }
            }))
        } else {
            None
        };

        // Run the traceroute probes
        let raw_hops = self.run_probes(target_ipv4).await?;

        // Process results
        let classified_hops = if self.config.enable_asn_lookup || self.config.enable_rdns {
            self.process_hops(raw_hops, target_ipv4).await?
        } else {
            // Convert raw hops to classified without enrichment
            raw_hops
                .into_iter()
                .map(|hop| ClassifiedHopInfo {
                    ttl: hop.ttl,
                    segment: SegmentType::Unknown,
                    hostname: None,
                    addr: hop.addr,
                    asn_info: None,
                    rtt: hop.rtt,
                })
                .collect()
        };

        // Get ISP info from parallel detection or provided IP
        let isp_info = if self.config.enable_asn_lookup {
            if let Some(public_ip) = self.config.public_ip {
                // Use provided public IP - check if we already have enrichment for it
                let existing_enrichment = {
                    let enrichment_results =
                        self.enrichment_results.lock().expect("mutex poisoned");
                    enrichment_results.get(&public_ip).cloned()
                };

                if let Some(enrichment) = existing_enrichment {
                    enrichment
                        .asn_info
                        .as_ref()
                        .map(|asn_info| crate::traceroute::IspInfo {
                            public_ip,
                            asn: asn_info.asn,
                            name: asn_info.name.clone(),
                            hostname: enrichment.hostname.clone(),
                        })
                } else {
                    // Need to look it up
                    match public_ip {
                        IpAddr::V4(ipv4) => {
                            if let Ok(asn_info) = lookup_asn(ipv4, None).await {
                                // Look up rDNS for provided public IP
                                let hostname =
                                    crate::dns::reverse_dns_lookup(public_ip, None).await.ok();

                                Some(crate::traceroute::IspInfo {
                                    public_ip,
                                    asn: asn_info.asn,
                                    name: asn_info.name,
                                    hostname,
                                })
                            } else {
                                None
                            }
                        }
                        IpAddr::V6(_) => {
                            // Fallback to detection for IPv6
                            detect_isp_with_default_resolver().await.ok()
                        }
                    }
                }
            } else if let Some(future) = public_ip_future {
                // Wait for parallel detection to complete
                match future.await {
                    Ok(Some((public_ip, asn_info, hostname))) => {
                        if let Some(asn) = asn_info {
                            Some(crate::traceroute::IspInfo {
                                public_ip,
                                asn: asn.asn,
                                name: asn.name,
                                hostname,
                            })
                        } else {
                            None
                        }
                    }
                    _ => None,
                }
            } else {
                None
            }
        } else {
            None
        };

        // Check if destination was reached
        let destination_reached = classified_hops
            .iter()
            .any(|hop| hop.is_destination(target_ip));

        Ok(TracerouteResult {
            target: self.config.target.clone(),
            target_ip,
            hops: classified_hops,
            isp_info,
            protocol_used: self.socket.mode().protocol,
            socket_mode_used: self.socket.mode().socket_mode,
            destination_reached,
            total_duration: start_time.elapsed(),
        })
    }

    /// Run the probe phase
    async fn run_probes(&self, target_ip: Ipv4Addr) -> Result<Vec<RawHopInfo>, TracerouteError> {
        debug_print!(1, "Starting probe phase for target {}", target_ip);
        let socket_arc = Arc::clone(&self.socket);
        let icmp_identifier = std::process::id() as u16;

        // Create event channel for communication
        let (event_tx, mut event_rx) = mpsc::channel::<TracerouteEvent>(256);

        // Create shutdown signal
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();

        // Spawn receiver task
        let recv_socket = Arc::clone(&socket_arc);
        let results_clone = Arc::clone(&self.results);
        let active_probes_clone = Arc::clone(&self.active_probes);
        let destination_reached_clone = Arc::clone(&self.destination_reached);
        let destination_ttl_clone = Arc::clone(&self.destination_ttl);
        let enrichment_enabled = self.config.enable_asn_lookup || self.config.enable_rdns;
        let enable_asn = self.config.enable_asn_lookup;
        let enable_rdns = self.config.enable_rdns;
        let enrichment_results_clone = Arc::clone(&self.enrichment_results);
        let receiver_poll_interval = crate::config::timing::receiver_poll_interval();
        let verbose = self.config.verbose;
        let event_tx_clone = event_tx.clone();
        let target_ip_v4 = target_ip;

        let receiver_handle = tokio::spawn(async move {
            // Set up resolver for enrichment
            let resolver = if enrichment_enabled {
                Some(Arc::new(crate::dns::create_default_resolver()))
            } else {
                None
            };

            loop {
                // Use select to wait for either a response or shutdown signal
                tokio::select! {
                    _ = &mut shutdown_rx => {
                        break;
                    }
                    _ = tokio::time::sleep(Duration::from_millis(0)) => {
                        // Try to receive a response with a short timeout
                        match recv_socket.recv_response(receiver_poll_interval) {
                    Ok(Some(response)) => {
                        debug_print!(2, "Received response: from={:?}, TTL={}, seq={}, RTT={:?}",
                            response.from_addr, response.probe_info.ttl,
                            response.probe_info.sequence, response.rtt);

                        // Remove from active probes
                        active_probes_clone
                            .lock()
                            .expect("mutex poisoned")
                            .remove(&response.probe_info.sequence);

                        // Store the result
                        let ttl = response.probe_info.ttl;
                        let raw_hop = RawHopInfo {
                            ttl,
                            addr: Some(response.from_addr),
                            rtt: Some(response.rtt),
                        };

                        // Check if destination reached
                        match response.response_type {
                            ResponseType::EchoReply | ResponseType::UdpPortUnreachable => {
                                if response.from_addr == IpAddr::V4(target_ip) {
                                    *destination_reached_clone.lock().expect("mutex poisoned") =
                                        true;

                                    // Record which TTL reached the destination
                                    let mut dest_ttl_guard =
                                        destination_ttl_clone.lock().expect("mutex poisoned");
                                    if dest_ttl_guard.is_none() {
                                        *dest_ttl_guard = Some(ttl);
                                    }
                                }
                            }
                            _ => {}
                        }

                        // Store result if not already present
                        let is_new = {
                            let mut results_guard = results_clone.lock().expect("mutex poisoned");
                            let is_new = !results_guard.contains_key(&ttl);
                            results_guard.entry(ttl).or_insert(raw_hop);
                            is_new
                        };

                        // Send response event
                        let _ = event_tx_clone.send(TracerouteEvent::ResponseReceived(response.clone())).await;

                        // Start enrichment immediately if this is a new IP
                        if is_new && enrichment_enabled {
                            let enrichment_guard =
                                enrichment_results_clone.lock().expect("mutex poisoned");
                            if !enrichment_guard.contains_key(&response.from_addr) {
                                drop(enrichment_guard);

                                // Spawn parallel enrichment tasks
                                let ip = response.from_addr;
                                let resolver_clone = resolver
                                    .as_ref()
                                    .expect("resolver should be Some when enrichment_enabled")
                                    .clone();
                                let enrichment_results_clone2 =
                                    Arc::clone(&enrichment_results_clone);

                                tokio::spawn(async move {
                                    // Run ASN and rDNS lookups in parallel (only if enabled)
                                    let asn_future = async {
                                        if enable_asn {
                                            if let IpAddr::V4(ipv4) = ip {
                                                lookup_asn(ipv4, Some(Arc::clone(&resolver_clone)))
                                                    .await
                                                    .ok()
                                            } else {
                                                None
                                            }
                                        } else {
                                            None
                                        }
                                    };

                                    let rdns_future = async {
                                        if enable_rdns {
                                            reverse_dns_lookup(
                                                ip,
                                                Some(Arc::clone(&resolver_clone)),
                                            )
                                            .await
                                            .ok()
                                        } else {
                                            None
                                        }
                                    };

                                    let (asn_info, hostname) =
                                        tokio::join!(asn_future, rdns_future);

                                    // Store the result
                                    enrichment_results_clone2
                                        .lock()
                                        .expect("mutex poisoned")
                                        .insert(
                                            ip,
                                            EnrichmentResult {
                                                ip,
                                                hostname,
                                                asn_info,
                                            },
                                        );
                                });
                            }
                        }
                    }
                    Ok(None) => {
                        // Timeout, continue
                    }
                    Err(e) => {
                        if verbose > 0 {
                            eprintln!("Error receiving response: {e}");
                        }
                    }
                }

                        // Check if destination reached from socket
                        if recv_socket.destination_reached() {
                            *destination_reached_clone.lock().expect("mutex poisoned") = true;
                        }
                    }
                }
            }
        });

        // Send probes
        let mut sequence = 1u16;
        debug_print!(
            1,
            "Starting to send probes, TTL range {}..={}",
            self.config.start_ttl,
            self.config.max_hops
        );

        for ttl_val in self.config.start_ttl..=self.config.max_hops {
            // Check if we should stop sending (destination found at lower TTL)
            {
                let dest_ttl = self.destination_ttl.lock().expect("mutex poisoned");
                if let Some(found_at_ttl) = *dest_ttl {
                    if ttl_val > found_at_ttl {
                        break; // Don't send probes beyond the destination
                    }
                }
            }

            // Set TTL
            self.socket
                .set_ttl(ttl_val)
                .map_err(|e| TracerouteError::ProbeSendError(e.to_string()))?;

            // Send multiple probes for this TTL
            for _query_num in 0..self.config.queries_per_hop {
                // Create probe info
                let probe_info = ProbeInfo {
                    ttl: ttl_val,
                    identifier: icmp_identifier,
                    sequence,
                    sent_at: Instant::now(),
                };

                // Track the probe
                self.active_probes
                    .lock()
                    .expect("mutex poisoned")
                    .insert(sequence, probe_info.clone());

                // Send the probe
                debug_print!(2, "Sending probe: TTL={}, seq={}", ttl_val, sequence);
                if let Err(e) = self.socket.send_probe(IpAddr::V4(target_ip), probe_info) {
                    if self.config.verbose > 0 {
                        eprintln!("Failed to send probe for TTL {ttl_val}: {e}");
                    }
                    self.active_probes
                        .lock()
                        .expect("mutex poisoned")
                        .remove(&sequence);
                }

                sequence += 1;

                // Add delay between queries if configured
                if _query_num < self.config.queries_per_hop - 1
                    && self.config.send_interval.as_millis() > 0
                {
                    tokio::time::sleep(self.config.send_interval).await;
                }
            }

            // Only add delay if configured and not last hop
            if self.config.send_interval.as_millis() > 0 && ttl_val < self.config.max_hops {
                tokio::time::sleep(self.config.send_interval).await;
            }
        }

        // Track total probes sent
        let total_probes_sent = (sequence - 1) as u32;

        // Spawn probe timeout checker task
        let active_probes_timeout = Arc::clone(&self.active_probes);
        let probe_timeout = self.config.probe_timeout;
        let event_tx_timeout = event_tx.clone();
        let timeout_checker = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(100));
            loop {
                interval.tick().await;
                let now = Instant::now();
                let mut timed_out = Vec::new();

                {
                    let active_guard = active_probes_timeout.lock().expect("mutex poisoned");
                    for (seq, probe) in active_guard.iter() {
                        if now.duration_since(probe.sent_at) >= probe_timeout {
                            timed_out.push(*seq);
                        }
                    }
                }

                // Remove timed out probes and send timeout events
                for seq in timed_out {
                    active_probes_timeout
                        .lock()
                        .expect("mutex poisoned")
                        .remove(&seq);
                    let _ = event_tx_timeout
                        .send(TracerouteEvent::ProbeTimeout { sequence: seq })
                        .await;
                }
            }
        });

        // Wait for responses using event-driven approach
        debug_print!(
            1,
            "Finished sending probes ({} total), waiting for responses (timeout={}ms)",
            total_probes_sent,
            self.config.overall_timeout.as_millis()
        );
        let completed_probes_clone = Arc::clone(&self.completed_probes);
        let overall_timeout = tokio::time::timeout(self.config.overall_timeout, async {
            loop {
                tokio::select! {
                    Some(event) = event_rx.recv() => {
                        match event {
                            TracerouteEvent::ResponseReceived(_) => {
                                // Increment completed probes count
                                *completed_probes_clone.lock().expect("mutex poisoned") += 1;

                                // Check if all probes completed
                                let completed = *completed_probes_clone.lock().expect("mutex poisoned");
                                if completed >= total_probes_sent {
                                    debug_print!(1, "All {} probes completed (responded or timed out)", total_probes_sent);
                                    let _ = event_tx.send(TracerouteEvent::AllProbesComplete).await;
                                    break;
                                }

                                // Check if we should continue
                                let (results_count, active_empty, dest_reached) = {
                                    let results_guard = self.results.lock().expect("mutex poisoned");
                                    let active_guard = self.active_probes.lock().expect("mutex poisoned");
                                    let dest_guard = self.destination_reached.lock().expect("mutex poisoned");
                                    (results_guard.len(), active_guard.is_empty(), *dest_guard)
                                };

                                if (dest_reached && active_empty)
                                    || (results_count >= (self.config.max_hops - self.config.start_ttl + 1) as usize
                                        && active_empty)
                                {
                                    debug_print!(1, "Exiting early: dest_reached={}, active_empty={}, results_count={}/{}",
                                        dest_reached, active_empty, results_count,
                                        self.config.max_hops - self.config.start_ttl + 1);
                                    let _ = event_tx.send(TracerouteEvent::AllProbesComplete).await;
                                    break;
                                }
                            }
                            TracerouteEvent::ProbeTimeout { .. } => {
                                // Increment completed probes count
                                *completed_probes_clone.lock().expect("mutex poisoned") += 1;

                                // Check if all probes completed
                                let completed = *completed_probes_clone.lock().expect("mutex poisoned");
                                if completed >= total_probes_sent {
                                    debug_print!(1, "All {} probes completed (responded or timed out)", total_probes_sent);
                                    let _ = event_tx.send(TracerouteEvent::AllProbesComplete).await;
                                    break;
                                }

                                // Check if all probes are done
                                let active_empty = self.active_probes.lock().expect("mutex poisoned").is_empty();
                                let dest_reached = *self.destination_reached.lock().expect("mutex poisoned");

                                if active_empty && dest_reached {
                                    let _ = event_tx.send(TracerouteEvent::AllProbesComplete).await;
                                    break;
                                }
                            }
                            #[cfg(target_os = "windows")]
                            TracerouteEvent::WindowsEventSignaled { sequence } => {
                                // Remove from active probes if still there
                                let removed = self.active_probes
                                    .lock()
                                    .expect("mutex poisoned")
                                    .remove(&sequence)
                                    .is_some();

                                if removed {
                                    // Increment completed probes count
                                    *completed_probes_clone.lock().expect("mutex poisoned") += 1;

                                    // Check if all probes completed
                                    let completed = *completed_probes_clone.lock().expect("mutex poisoned");
                                    if completed >= total_probes_sent {
                                        debug_print!(1, "All {} probes completed (responded or timed out)", total_probes_sent);
                                        let _ = event_tx.send(TracerouteEvent::AllProbesComplete).await;
                                        break;
                                    }
                                }
                            }
                            TracerouteEvent::DestinationReached { ttl } => {
                                *self.destination_ttl.lock().expect("mutex poisoned") = Some(ttl);
                            }
                            TracerouteEvent::AllProbesComplete => {
                                break;
                            }
                        }
                    }
                }
            }
        });

        // Wait for completion or timeout
        debug_print!(1, "Starting wait for responses or timeout");
        let timeout_result = overall_timeout.await;
        debug_print!(1, "Wait completed, timed_out={}", timeout_result.is_err());

        // Signal shutdown
        let _ = shutdown_tx.send(());
        timeout_checker.abort();

        // Wait for receiver to finish
        debug_print!(1, "Waiting for receiver to finish");
        let _ = receiver_handle.await;
        debug_print!(1, "Receiver finished");

        // Extract results
        let results_guard = self.results.lock().expect("mutex poisoned");
        let mut hops: Vec<RawHopInfo> = Vec::new();

        // Determine the actual max TTL to process
        let display_max_ttl = {
            let mut dest_ttl = self.config.max_hops;
            for ttl in self.config.start_ttl..=self.config.max_hops {
                if let Some(hop) = results_guard.get(&ttl) {
                    if hop.addr == Some(IpAddr::V4(target_ip_v4)) {
                        dest_ttl = ttl;
                        break;
                    }
                }
            }
            dest_ttl
        };

        // Collect all hops
        for ttl in self.config.start_ttl..=display_max_ttl {
            if let Some(hop) = results_guard.get(&ttl) {
                hops.push(hop.clone());
            } else {
                // Add empty hop
                hops.push(RawHopInfo {
                    ttl,
                    addr: None,
                    rtt: None,
                });
            }
        }

        Ok(hops)
    }

    /// Process hops with enrichment (ASN lookup and classification)
    async fn process_hops(
        &self,
        raw_hops: Vec<RawHopInfo>,
        _target_ip: Ipv4Addr,
    ) -> Result<Vec<ClassifiedHopInfo>, TracerouteError> {
        // Wait a bit for any remaining enrichment tasks to complete
        tokio::time::sleep(crate::config::timing::enrichment_wait_time()).await;

        // Get enrichment results
        let enrichment_results = self.enrichment_results.lock().expect("mutex poisoned");

        // Find the public IP enrichment result to get ISP ASN
        let isp_asn = if self.config.enable_asn_lookup {
            // Look for the public IP in enrichment results
            let public_ip = if let Some(ip) = self.config.public_ip {
                Some(ip)
            } else {
                // Find the first non-private IP with ASN info - that's likely our public IP
                enrichment_results
                    .values()
                    .find(|e| {
                        if let (IpAddr::V4(ipv4), Some(asn)) = (e.ip, &e.asn_info) {
                            !crate::traceroute::is_internal_ip(&ipv4) && asn.asn != 0
                        } else {
                            false
                        }
                    })
                    .map(|e| e.ip)
            };

            public_ip.and_then(|ip| {
                enrichment_results
                    .get(&ip)
                    .and_then(|e| e.asn_info.as_ref())
                    .map(|asn| asn.asn)
            })
        } else {
            None
        };

        // Build final classified hops
        let mut classified_hops = Vec::new();
        let mut in_isp_segment = false;

        for raw_hop in raw_hops {
            // Get pre-computed enrichment data for this hop
            let enrichment = raw_hop.addr.and_then(|addr| enrichment_results.get(&addr));
            let asn_info = if self.config.enable_asn_lookup {
                enrichment.and_then(|e| e.asn_info.clone())
            } else {
                None
            };
            let hostname = if self.config.enable_rdns {
                enrichment.and_then(|e| e.hostname.clone())
            } else {
                None
            };

            let segment = if let Some(IpAddr::V4(ipv4)) = raw_hop.addr {
                if crate::traceroute::is_internal_ip(&ipv4) {
                    SegmentType::Lan
                } else if crate::traceroute::is_cgnat(&ipv4) {
                    // CGNAT addresses belong to ISP, not LAN
                    in_isp_segment = true;
                    SegmentType::Isp
                } else if let Some(ref isp) = isp_asn {
                    if let Some(ref asn) = asn_info {
                        if asn.asn == *isp {
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

            classified_hops.push(ClassifiedHopInfo {
                ttl: raw_hop.ttl,
                segment,
                hostname,
                addr: raw_hop.addr,
                asn_info,
                rtt: raw_hop.rtt,
            });
        }

        Ok(classified_hops)
    }

    /// Get current progress (for streaming updates)
    pub fn get_progress(&self) -> TracerouteProgress {
        let results_guard = self.results.lock().expect("mutex poisoned");
        let dest_guard = self.destination_reached.lock().expect("mutex poisoned");

        TracerouteProgress {
            current_ttl: results_guard
                .keys()
                .max()
                .copied()
                .unwrap_or(self.config.start_ttl),
            max_ttl: self.config.max_hops,
            hops_discovered: results_guard.len(),
            destination_reached: *dest_guard,
            elapsed: Duration::from_secs(0), // Would need to track start time for this
        }
    }
}

/// Resolve hostname to IP address
async fn resolve_host(host: &str) -> Result<IpAddr, TracerouteError> {
    // Try parsing as IP first
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(ip);
    }

    // Resolve hostname
    let resolver = TokioResolver::builder_with_config(
        ResolverConfig::cloudflare(),
        TokioConnectionProvider::default(),
    )
    .build();

    // Try IPv4 first
    match resolver.ipv4_lookup(host).await {
        Ok(lookup) => {
            if let Some(ipv4) = lookup.iter().next() {
                return Ok(IpAddr::V4(ipv4.0));
            }
        }
        Err(_) => {}
    }

    // Try IPv6
    match resolver.ipv6_lookup(host).await {
        Ok(lookup) => {
            if let Some(ipv6) = lookup.iter().next() {
                return Ok(IpAddr::V6(ipv6.0));
            }
        }
        Err(_) => {}
    }

    Err(TracerouteError::ResolutionError(format!(
        "Failed to resolve host: {host}"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_resolve_host_ip() {
        // Test with IPv4 address
        let result = resolve_host("8.8.8.8").await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));

        // Test with IPv6 address
        let result = resolve_host("::1").await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), IpAddr::V6("::1".parse().unwrap()));
    }

    #[tokio::test]
    async fn test_resolve_host_invalid() {
        let result = resolve_host("invalid.host.that.does.not.exist.example").await;
        assert!(result.is_err());
    }
}
