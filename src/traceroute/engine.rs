//! Core traceroute engine implementation

#![allow(clippy::single_match)]
#![allow(clippy::nonminimal_bool)]

use crate::asn::lookup_asn;
use crate::dns::reverse_dns_lookup;
use crate::public_ip::detect_isp_with_default_resolver;
use crate::socket::{ProbeInfo, ProbeSocket, ResponseType};
use crate::traceroute::{
    ClassifiedHopInfo, RawHopInfo, SegmentType, TracerouteConfig, TracerouteProgress,
    TracerouteResult,
};
use futures::stream::{FuturesUnordered, StreamExt};
use hickory_resolver::config::ResolverConfig;
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::TokioResolver;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Error type for traceroute operations
#[derive(Debug, thiserror::Error)]
pub enum TracerouteError {
    /// Socket creation failed
    #[error("Failed to create socket: {0}")]
    SocketError(String),

    /// DNS resolution failed
    #[error("Failed to resolve host: {0}")]
    ResolutionError(String),

    /// Probe sending failed
    #[error("Failed to send probe: {0}")]
    ProbeSendError(String),

    /// Configuration error
    #[error("Configuration error: {0}")]
    ConfigError(String),

    /// Target is IPv6 (not yet supported)
    #[error("IPv6 targets are not yet supported")]
    Ipv6NotSupported,
}

/// Traceroute engine
pub struct TracerouteEngine {
    config: TracerouteConfig,
    socket: Arc<Box<dyn ProbeSocket>>,
    results: Arc<Mutex<HashMap<u8, RawHopInfo>>>,
    active_probes: Arc<Mutex<HashMap<u16, ProbeInfo>>>,
    destination_reached: Arc<Mutex<bool>>,
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

        // Detect ISP if enabled
        let isp_info = if self.config.enable_asn_lookup {
            if let Some(public_ip) = self.config.public_ip {
                // Use provided public IP
                match public_ip {
                    IpAddr::V4(ipv4) => {
                        if let Ok(asn_info) = lookup_asn(ipv4, None).await {
                            Some(crate::traceroute::IspInfo {
                                public_ip,
                                asn: asn_info.asn,
                                name: asn_info.name,
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
            } else {
                // Detect public IP
                detect_isp_with_default_resolver().await.ok()
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
        let socket_arc = Arc::clone(&self.socket);
        let icmp_identifier = std::process::id() as u16;

        // Spawn receiver task
        let recv_socket = Arc::clone(&socket_arc);
        let results_clone = Arc::clone(&self.results);
        let active_probes_clone = Arc::clone(&self.active_probes);
        let destination_reached_clone = Arc::clone(&self.destination_reached);
        let overall_timeout = self.config.overall_timeout;

        let receiver_handle = tokio::spawn(async move {
            let receiver_start_time = Instant::now();

            loop {
                if receiver_start_time.elapsed() > overall_timeout + Duration::from_millis(1000) {
                    break;
                }

                // Try to receive a response
                match recv_socket.recv_response(Duration::from_millis(100)) {
                    Ok(Some(response)) => {
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
                                }
                            }
                            _ => {}
                        }

                        // Store result if not already present
                        let mut results_guard = results_clone.lock().expect("mutex poisoned");
                        results_guard.entry(ttl).or_insert(raw_hop);
                    }
                    Ok(None) => {
                        // Timeout, continue
                    }
                    Err(e) => {
                        eprintln!("Error receiving response: {e}");
                    }
                }

                // Check if destination reached from socket
                if recv_socket.destination_reached() {
                    *destination_reached_clone.lock().expect("mutex poisoned") = true;
                }
            }
        });

        // Send probes
        let mut sequence = 1u16;

        for ttl_val in self.config.start_ttl..=self.config.max_hops {
            // Set TTL
            self.socket
                .set_ttl(ttl_val)
                .map_err(|e| TracerouteError::ProbeSendError(e.to_string()))?;

            // Send multiple probes for this TTL
            for query_num in 0..self.config.queries_per_hop {
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
                if let Err(e) = self.socket.send_probe(IpAddr::V4(target_ip), probe_info) {
                    eprintln!("Failed to send probe for TTL {ttl_val}: {e}");
                    self.active_probes
                        .lock()
                        .expect("mutex poisoned")
                        .remove(&sequence);
                }

                sequence += 1;

                // Small delay between probes for the same TTL
                if query_num < self.config.queries_per_hop - 1 {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }

            // Delay between different TTLs
            if self.config.send_interval.as_millis() > 0 {
                tokio::time::sleep(self.config.send_interval).await;
            }
        }

        // Wait for responses
        let overall_start_time = Instant::now();
        loop {
            let (results_count, active_empty, dest_reached) = {
                let results_guard = self.results.lock().expect("mutex poisoned");
                let active_guard = self.active_probes.lock().expect("mutex poisoned");
                let dest_guard = self.destination_reached.lock().expect("mutex poisoned");
                (results_guard.len(), active_guard.is_empty(), *dest_guard)
            };

            // Check if we have a complete path to destination
            if dest_reached {
                let results_guard = self.results.lock().expect("mutex poisoned");
                let mut have_complete_path = true;

                // Find the highest TTL that reached the destination
                let mut dest_ttl = self.config.start_ttl;
                for ttl in self.config.start_ttl..=self.config.max_hops {
                    if let Some(hop) = results_guard.get(&ttl) {
                        if hop.addr == Some(IpAddr::V4(target_ip)) {
                            dest_ttl = ttl;
                            break;
                        }
                    }
                }

                // Check if we have all hops from start to destination
                for ttl in self.config.start_ttl..=dest_ttl {
                    if !results_guard.contains_key(&ttl) {
                        have_complete_path = false;
                        break;
                    }
                }

                if have_complete_path {
                    break;
                }
            }

            if (dest_reached && active_empty)
                || (results_count >= (self.config.max_hops - self.config.start_ttl + 1) as usize
                    && active_empty)
            {
                break;
            }

            if overall_start_time.elapsed() > self.config.overall_timeout {
                break;
            }

            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        // Abort receiver
        receiver_handle.abort();

        // Extract results
        let results_guard = self.results.lock().expect("mutex poisoned");
        let mut hops: Vec<RawHopInfo> = Vec::new();

        // Determine the actual max TTL to process
        let display_max_ttl = {
            let mut dest_ttl = self.config.max_hops;
            for ttl in self.config.start_ttl..=self.config.max_hops {
                if let Some(hop) = results_guard.get(&ttl) {
                    if hop.addr == Some(IpAddr::V4(target_ip)) {
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
        let resolver = Arc::new(
            TokioResolver::builder_with_config(
                ResolverConfig::cloudflare(),
                TokioConnectionProvider::default(),
            )
            .build(),
        );

        // Prepare for parallel lookups
        let mut hops_to_enrich = Vec::new();
        for (idx, hop) in raw_hops.iter().enumerate() {
            let ipv4_addr_opt = match hop.addr {
                Some(IpAddr::V4(ipv4)) => Some(ipv4),
                _ => None,
            };
            hops_to_enrich.push((idx, hop.clone(), ipv4_addr_opt));
        }

        let mut asn_results: HashMap<usize, Option<crate::traceroute::AsnInfo>> = HashMap::new();
        let mut rdns_results: HashMap<usize, Option<String>> = HashMap::new();

        // Perform parallel lookups
        let mut asn_futures = FuturesUnordered::new();
        let mut rdns_futures = FuturesUnordered::new();

        for (idx, hop, ipv4_addr_opt) in &hops_to_enrich {
            // ASN lookup
            if self.config.enable_asn_lookup {
                if let Some(ipv4_addr) = ipv4_addr_opt {
                    let resolver_clone = Arc::clone(&resolver);
                    let ip_to_lookup = *ipv4_addr;
                    let idx_copy = *idx;
                    asn_futures.push(async move {
                        let asn_opt = lookup_asn(ip_to_lookup, Some(resolver_clone)).await.ok();
                        (idx_copy, asn_opt)
                    });
                }
            }

            // Reverse DNS lookup
            if self.config.enable_rdns {
                if let Some(addr) = hop.addr {
                    let resolver_clone = Arc::clone(&resolver);
                    let ip_to_lookup = addr;
                    let idx_copy = *idx;
                    rdns_futures.push(async move {
                        let hostname = reverse_dns_lookup(ip_to_lookup, Some(resolver_clone))
                            .await
                            .ok();
                        (idx_copy, hostname)
                    });
                }
            }
        }

        // Collect ASN results
        while let Some((idx, asn_opt)) = asn_futures.next().await {
            asn_results.insert(idx, asn_opt);
        }

        // Collect rDNS results
        while let Some((idx, hostname_opt)) = rdns_futures.next().await {
            rdns_results.insert(idx, hostname_opt);
        }

        // Determine ISP ASN
        let isp_asn: Option<String> = if self.config.enable_asn_lookup {
            detect_isp_with_default_resolver()
                .await
                .ok()
                .map(|isp| isp.asn)
        } else {
            None
        };

        // Build final classified hops
        let mut classified_hops = Vec::new();
        let mut in_isp_segment = false;

        for (idx, (_, raw_hop, ipv4_addr_opt)) in hops_to_enrich.iter().enumerate() {
            let asn_info = asn_results.get(&idx).and_then(std::clone::Clone::clone);
            let hostname = rdns_results.get(&idx).and_then(std::clone::Clone::clone);

            let segment = if let Some(ipv4_addr) = ipv4_addr_opt {
                if crate::traceroute::is_internal_ip(ipv4_addr)
                    || crate::traceroute::is_cgnat(ipv4_addr)
                {
                    SegmentType::Lan
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
