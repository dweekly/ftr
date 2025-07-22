//! ftr - Fast TraceRoute: A parallel ICMP traceroute implementation with ASN lookup.
//!
//! This crate provides a high-performance traceroute tool that uses parallel
//! probing to significantly reduce scan time compared to traditional sequential
//! implementations. It includes automatic ASN (Autonomous System Number) lookups
//! and intelligent hop classification.

#![allow(clippy::single_match)] // Match is clearer for error handling in some cases
#![allow(clippy::nonminimal_bool)] // Complex boolean logic is clearer as written

use anyhow::{Context, Result};
use clap::Parser;
use futures::stream::{FuturesUnordered, StreamExt};
use hickory_resolver::config::ResolverConfig;
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::TokioResolver;
use ipnet::Ipv4Net;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

// Import from our library
use ftr::socket::{ProbeInfo, ProbeSocket, ResponseType};
use ftr::{create_probe_socket_with_mode, ProbeProtocol, SocketMode};

/// Default overall timeout for the entire traceroute operation if not all replies received.
const DEFAULT_OVERALL_TIMEOUT_MS: u64 = 3000;
/// Global cache for ASN lookups by CIDR prefix
static ASN_CACHE: std::sync::LazyLock<std::sync::Mutex<HashMap<Ipv4Net, AsnInfo>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(HashMap::new()));

/// Command-line arguments for the traceroute tool.
#[derive(Parser, Debug)]
#[clap(author, version, about = "Fast parallel ICMP traceroute with ASN lookup", long_about = None)]
struct Args {
    host: String,
    #[clap(short, long, default_value_t = 1)]
    start_ttl: u8,
    #[clap(short = 'm', long, default_value_t = 30)]
    max_hops: u8,
    #[clap(long, default_value_t = 1000)]
    probe_timeout_ms: u64,
    #[clap(short = 'i', long, default_value_t = 5)]
    send_launch_interval_ms: u64,
    #[clap(short = 'W', long, default_value_t = DEFAULT_OVERALL_TIMEOUT_MS)]
    overall_timeout_ms: u64,
    #[clap(long, help = "Disable ASN lookup and segment classification")]
    no_enrich: bool,
    #[clap(long, help = "Disable reverse DNS lookups")]
    no_rdns: bool,
    #[clap(long, value_enum, help = "Protocol to use (icmp, udp)")]
    protocol: Option<ProtocolArg>,
    #[clap(long, value_enum, help = "Socket mode to use (raw, dgram)")]
    socket_mode: Option<SocketModeArg>,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum ProtocolArg {
    Icmp,
    Udp,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum SocketModeArg {
    Raw,
    Dgram,
}

/// Represents ASN information for an IP address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsnInfo {
    /// Autonomous System Number (e.g., "13335")
    pub asn: String,
    /// IP prefix/CIDR block (e.g., "104.16.0.0/12")
    pub prefix: String,
    /// Two-letter country code (e.g., "US")
    pub country_code: String,
    /// Regional Internet Registry (e.g., "ARIN")
    pub registry: String,
    /// AS name/organization (e.g., "CLOUDFLARENET")
    pub name: String,
}

/// Intermediate hop information collected during traceroute.
#[derive(Debug, Clone)]
struct RawHopInfo {
    ttl: u8,
    addr: Option<IpAddr>,
    rtt: Option<Duration>,
}

/// Classification of a hop's network segment.
#[derive(Debug, Clone, PartialEq, Eq)]
enum SegmentType {
    Lan,
    Isp,
    Beyond,
    Unknown,
}

impl std::fmt::Display for SegmentType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SegmentType::Lan => write!(f, "LAN   "),
            SegmentType::Isp => write!(f, "ISP   "),
            SegmentType::Beyond => write!(f, "BEYOND"),
            SegmentType::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

/// Final hop information with ASN data and classification.
#[derive(Debug, Clone)]
struct ClassifiedHopInfo {
    ttl: u8,
    segment: SegmentType,
    hostname: Option<String>,
    addr: Option<IpAddr>,
    asn_info: Option<AsnInfo>,
    rtt: Option<Duration>,
}

/// Perform reverse DNS lookup for an IP address
async fn reverse_dns_lookup(ip: IpAddr, resolver: &TokioResolver) -> Option<String> {
    match resolver.reverse_lookup(ip).await {
        Ok(lookup) => {
            // Get the first PTR record
            lookup.iter().next().map(|name| {
                let name_str = name.to_string();
                // Remove trailing dot if present
                if name_str.ends_with('.') {
                    name_str[..name_str.len() - 1].to_string()
                } else {
                    name_str
                }
            })
        }
        Err(_) => None,
    }
}

/// Performs ASN lookup using Team Cymru's whois service
async fn lookup_asn(ipv4_addr: Ipv4Addr, resolver: &Arc<TokioResolver>) -> Option<AsnInfo> {
    // Check if it's a private or special IP
    if is_internal_ip(&ipv4_addr)
        || ipv4_addr.is_link_local()
        || ipv4_addr.is_broadcast()
        || ipv4_addr.is_documentation()
        || ipv4_addr.is_unspecified()
    {
        let name = if ipv4_addr.is_loopback() {
            "Loopback"
        } else if ipv4_addr.is_private() {
            "Private Network"
        } else if is_cgnat(&ipv4_addr) {
            "Carrier Grade NAT"
        } else {
            "Special Use"
        }
        .to_string();
        return Some(AsnInfo {
            asn: "N/A".to_string(),
            prefix: ipv4_addr.to_string() + "/32",
            country_code: "N/A".to_string(),
            registry: "N/A".to_string(),
            name,
        });
    }

    // Check cache first
    {
        let cache = ASN_CACHE.lock().expect("mutex poisoned");
        for (prefix, asn_info) in cache.iter() {
            if prefix.contains(&ipv4_addr) {
                return Some(asn_info.clone());
            }
        }
    }

    // Not in cache, perform lookup
    let octets = ipv4_addr.octets();
    let query = format!(
        "{}.{}.{}.{}.origin.asn.cymru.com",
        octets[3], octets[2], octets[1], octets[0]
    );
    match resolver.txt_lookup(query).await {
        Ok(lookup) => {
            if let Some(record) = lookup.iter().next() {
                let txt_data = record
                    .iter()
                    .map(|data| String::from_utf8_lossy(data))
                    .collect::<Vec<_>>()
                    .join("");

                let parts: Vec<&str> = txt_data.split('|').map(str::trim).collect();
                if parts.len() >= 3 {
                    let asn = parts[0].to_string();
                    let prefix = parts[1].to_string();
                    let country_code = parts[2].to_string();
                    let registry = if parts.len() > 3 {
                        parts[3].to_string()
                    } else {
                        String::new()
                    };

                    // Parse prefix to create Ipv4Net
                    if let Ok(net) = prefix.parse::<Ipv4Net>() {
                        // Query for AS name
                        let as_query = format!("AS{asn}.asn.cymru.com");
                        let name = match resolver.txt_lookup(as_query).await {
                            Ok(as_lookup) => {
                                if let Some(as_record) = as_lookup.iter().next() {
                                    let as_txt = as_record
                                        .iter()
                                        .map(|data| String::from_utf8_lossy(data))
                                        .collect::<Vec<_>>()
                                        .join("");
                                    let as_parts: Vec<&str> =
                                        as_txt.split('|').map(str::trim).collect();
                                    if as_parts.len() >= 5 {
                                        as_parts[4].to_string()
                                    } else {
                                        String::new()
                                    }
                                } else {
                                    String::new()
                                }
                            }
                            Err(_) => String::new(),
                        };

                        let asn_info = AsnInfo {
                            asn,
                            prefix: prefix.clone(),
                            country_code,
                            registry,
                            name,
                        };

                        // Cache the result
                        ASN_CACHE
                            .lock()
                            .expect("mutex poisoned")
                            .insert(net, asn_info.clone());

                        return Some(asn_info);
                    }
                }
            }
        }
        Err(_) => {}
    }
    None
}

/// Queries the public IP and returns the ASN information
async fn get_public_ip(_resolver: Option<&Arc<TokioResolver>>) -> Result<Ipv4Addr> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;

    let response = client
        .get("https://checkip.amazonaws.com")
        .send()
        .await
        .context("Failed to query public IP")?;

    let ip_str = response
        .text()
        .await
        .context("Failed to read response body")?
        .trim()
        .to_string();

    ip_str
        .parse::<Ipv4Addr>()
        .context("Failed to parse IP address")
}

/// Detect ISP from public IP
async fn detect_isp_from_public_ip() -> Option<(String, String)> {
    let resolver = Arc::new(
        TokioResolver::builder_with_config(
            ResolverConfig::cloudflare(),
            TokioConnectionProvider::default(),
        )
        .build(),
    );

    if let Ok(public_ip) = get_public_ip(Some(&resolver)).await {
        if let Some(asn_info) = lookup_asn(public_ip, &resolver).await {
            return Some((asn_info.asn.clone(), asn_info.name.clone()));
        }
    }
    None
}

/// Resolve hostname to IPv4 address
async fn resolve_host(host: &str) -> Result<Ipv4Addr> {
    // Try parsing as IP first
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        return Ok(ip);
    }

    // Resolve hostname
    let resolver = TokioResolver::builder_with_config(
        ResolverConfig::cloudflare(),
        TokioConnectionProvider::default(),
    )
    .build();

    let lookup = resolver
        .ipv4_lookup(host)
        .await
        .context(format!("Failed to resolve host: {host}"))?;

    lookup
        .iter()
        .next()
        .map(|rdata| rdata.0)
        .ok_or_else(|| anyhow::anyhow!("No IPv4 address found for {}", host))
}

/// Checks if an IP is in a private/internal range
fn is_internal_ip(ip: &Ipv4Addr) -> bool {
    ip.is_private() || ip.is_loopback() || ip.is_link_local()
}

/// Checks if an IP is in the CGNAT range (100.64.0.0/10)
fn is_cgnat(ip: &Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 100 && octets[1] >= 64 && octets[1] <= 127
}

/// Print raw hop information
fn print_raw_hop_info(hop: &RawHopInfo) {
    match (hop.addr, hop.rtt) {
        (Some(addr), Some(rtt)) => {
            println!(
                "{:2} {} ({:.3} ms)",
                hop.ttl,
                addr,
                rtt.as_secs_f64() * 1000.0
            );
        }
        _ => {
            println!("{:2} * * *", hop.ttl);
        }
    }
}

/// Print classified hop information with enrichment
fn print_classified_hop_info(hop: &ClassifiedHopInfo) {
    let addr_str = hop.addr.map_or("*".to_string(), |a| a.to_string());
    let rtt_str = hop.rtt.map_or("*".to_string(), |r| {
        format!("{:.3} ms", r.as_secs_f64() * 1000.0)
    });

    let hostname_str = hop.hostname.as_deref().unwrap_or(&addr_str);

    // Format ASN info
    let asn_str = if let Some(asn_info) = &hop.asn_info {
        if asn_info.asn != "N/A" {
            format!(" [AS{} {}]", asn_info.asn, asn_info.name)
        } else {
            String::new()
        }
    } else {
        String::new()
    };

    println!(
        "{:2} [{}] {} {}{}",
        hop.ttl, hop.segment, hostname_str, rtt_str, asn_str
    );
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let effective_max_hops = args.max_hops;

    let target_ipv4 = match resolve_host(&args.host).await {
        Ok(ip) => ip,
        Err(e) => {
            eprintln!("Error resolving host {}: {}", args.host, e);
            return Ok(());
        }
    };

    println!(
        "ftr to {} ({}), {} max hops, {}ms probe timeout, {}ms overall timeout{}",
        args.host,
        target_ipv4,
        effective_max_hops,
        args.probe_timeout_ms,
        args.overall_timeout_ms,
        if args.no_enrich {
            " (enrichment disabled)"
        } else {
            ""
        }
    );

    let icmp_identifier = std::process::id() as u16;

    // Convert command-line args to socket abstraction types
    let preferred_protocol = args.protocol.map(|p| match p {
        ProtocolArg::Icmp => ProbeProtocol::Icmp,
        ProtocolArg::Udp => ProbeProtocol::Udp,
    });

    let preferred_mode = args.socket_mode.map(|m| match m {
        SocketModeArg::Raw => SocketMode::Raw,
        SocketModeArg::Dgram => SocketMode::Dgram,
    });

    // Create socket using the abstraction layer
    let probe_socket =
        create_probe_socket_with_mode(IpAddr::V4(target_ipv4), preferred_protocol, preferred_mode)?;

    let raw_results_map: Arc<Mutex<HashMap<u8, RawHopInfo>>> = Arc::new(Mutex::new(HashMap::new()));
    let active_probes: Arc<Mutex<HashMap<u16, ProbeInfo>>> = Arc::new(Mutex::new(HashMap::new()));
    let destination_reached = Arc::new(Mutex::new(false));

    let socket_arc: Arc<Box<dyn ProbeSocket>> = Arc::new(probe_socket);

    // Inform users about UDP port selection
    if matches!(socket_arc.mode().protocol, ProbeProtocol::Udp) {
        eprintln!();
        eprintln!(
            "Note: Using UDP port 443 (HTTPS/QUIC) for better path visibility through firewalls."
        );
        eprintln!("      Traditional UDP traceroute ports (33434+) are often filtered by routers.");
        eprintln!();
    }

    // Spawn receiver task
    let recv_socket_clone = Arc::clone(&socket_arc);
    let results_clone_recv = Arc::clone(&raw_results_map);
    let active_probes_clone_recv = Arc::clone(&active_probes);
    let destination_reached_clone_recv = Arc::clone(&destination_reached);
    let actual_target_ip_for_receiver = target_ipv4;

    let receiver_handle = tokio::spawn(async move {
        let receiver_start_time = Instant::now();

        loop {
            if receiver_start_time.elapsed() > Duration::from_millis(args.overall_timeout_ms + 1000)
            {
                break;
            }

            // Try to receive a response
            match recv_socket_clone.recv_response(Duration::from_millis(100)) {
                Ok(Some(response)) => {
                    // Remove from active probes
                    active_probes_clone_recv
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
                            if response.from_addr == IpAddr::V4(actual_target_ip_for_receiver) {
                                *destination_reached_clone_recv
                                    .lock()
                                    .expect("mutex poisoned") = true;
                            }
                        }
                        _ => {}
                    }

                    // Store result if not already present
                    let mut results_guard = results_clone_recv.lock().expect("mutex poisoned");
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
            if recv_socket_clone.destination_reached() {
                *destination_reached_clone_recv
                    .lock()
                    .expect("mutex poisoned") = true;
            }
        }
    });

    // Send probes sequentially to avoid TTL race conditions
    let mut sequence = 1u16;

    for ttl_val in args.start_ttl..=effective_max_hops {
        // Set TTL
        if let Err(e) = socket_arc.set_ttl(ttl_val) {
            eprintln!("Failed to set TTL {ttl_val}: {e}");
            continue;
        }

        // Create probe info
        let probe_info = ProbeInfo {
            ttl: ttl_val,
            identifier: icmp_identifier,
            sequence,
            sent_at: Instant::now(),
        };

        // Track the probe
        active_probes
            .lock()
            .expect("mutex poisoned")
            .insert(sequence, probe_info.clone());

        // Send the probe
        if let Err(e) = socket_arc.send_probe(IpAddr::V4(target_ipv4), probe_info) {
            eprintln!("Failed to send probe for TTL {ttl_val}: {e}");
            active_probes
                .lock()
                .expect("mutex poisoned")
                .remove(&sequence);
        }

        sequence += 1;

        // For UDP with IP_RECVERR, wait a bit to ensure we receive the response
        // before sending the next probe
        if matches!(socket_arc.mode().protocol, ProbeProtocol::Udp) {
            tokio::time::sleep(Duration::from_millis(100)).await;
        } else if args.send_launch_interval_ms > 0 {
            tokio::time::sleep(Duration::from_millis(args.send_launch_interval_ms)).await;
        }
    }

    // All probes sent

    // Wait for responses
    let overall_start_time = Instant::now();
    loop {
        let (results_count, active_empty, dest_reached) = {
            let results_guard = raw_results_map.lock().expect("mutex poisoned");
            let active_guard = active_probes.lock().expect("mutex poisoned");
            let dest_guard = destination_reached.lock().expect("mutex poisoned");
            (results_guard.len(), active_guard.is_empty(), *dest_guard)
        };

        // Check if we have a complete path to destination
        if dest_reached {
            let results_guard = raw_results_map.lock().expect("mutex poisoned");
            let mut have_complete_path = true;

            // Find the highest TTL that reached the destination
            let mut dest_ttl = args.start_ttl;
            for ttl in args.start_ttl..=effective_max_hops {
                if let Some(hop) = results_guard.get(&ttl) {
                    if hop.addr == Some(IpAddr::V4(target_ipv4)) {
                        dest_ttl = ttl;
                        break;
                    }
                }
            }

            // Check if we have all hops from start to destination
            for ttl in args.start_ttl..=dest_ttl {
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
            || (results_count >= (effective_max_hops - args.start_ttl + 1) as usize && active_empty)
        {
            break;
        }

        if overall_start_time.elapsed() > Duration::from_millis(args.overall_timeout_ms) {
            break;
        }

        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Abort receiver
    receiver_handle.abort();

    // Process and display results
    if !args.no_enrich {
        println!(
            "\nPerforming ASN lookups{} and classifying segments...",
            if args.no_rdns {
                ""
            } else {
                ", reverse DNS lookups"
            }
        );

        let final_classified_hops = process_hops_for_asn_and_classification(
            args.start_ttl,
            effective_max_hops,
            raw_results_map,
            args.no_enrich,
            target_ipv4,
            args.no_rdns,
        )
        .await?;

        // Print enriched results
        for hop_info in &final_classified_hops {
            print_classified_hop_info(hop_info);
        }

        // Detect and print ISP info
        if let Some((isp_asn, isp_name)) = detect_isp_from_public_ip().await {
            println!("\nDetected ISP: AS{isp_asn} ({isp_name})");
        }
    } else {
        // Print raw results
        println!("\nTraceroute path (raw):");
        let results_guard = raw_results_map.lock().expect("mutex poisoned");
        for ttl_val in args.start_ttl..=effective_max_hops {
            if let Some(raw_hop) = results_guard.get(&ttl_val) {
                print_raw_hop_info(raw_hop);
            } else {
                println!("{ttl_val:2} * * *");
            }
        }
    }

    Ok(())
}

/// Performs ASN lookups and classifies hops into LAN, ISP, or BEYOND.
async fn process_hops_for_asn_and_classification(
    start_ttl: u8,
    max_ttl: u8,
    raw_results_map_arc: Arc<Mutex<HashMap<u8, RawHopInfo>>>,
    no_asn: bool,
    _target_ip: Ipv4Addr,
    no_rdns: bool,
) -> Result<Vec<ClassifiedHopInfo>> {
    let resolver = if !no_asn || !no_rdns {
        Some(Arc::new(
            TokioResolver::builder_with_config(
                ResolverConfig::cloudflare(),
                TokioConnectionProvider::default(),
            )
            .build(),
        ))
    } else {
        None
    };

    let raw_results_map = raw_results_map_arc.lock().expect("mutex poisoned").clone();
    let mut hops_to_enrich = Vec::new();

    for ttl in start_ttl..=max_ttl {
        if let Some(raw_hop) = raw_results_map.get(&ttl) {
            let ipv4_addr_opt = match raw_hop.addr {
                Some(IpAddr::V4(ipv4)) => Some(ipv4),
                _ => None,
            };
            hops_to_enrich.push((hops_to_enrich.len(), raw_hop.clone(), ipv4_addr_opt));
        } else {
            hops_to_enrich.push((
                hops_to_enrich.len(),
                RawHopInfo {
                    ttl,
                    addr: None,
                    rtt: None,
                },
                None,
            ));
        }
    }

    let mut asn_results: HashMap<usize, Option<AsnInfo>> = HashMap::new();
    let resolver_for_futures = match &resolver {
        Some(r) => r.clone(),
        None => Arc::new(
            TokioResolver::builder_with_config(
                ResolverConfig::cloudflare(),
                TokioConnectionProvider::default(),
            )
            .build(),
        ),
    };

    // Perform ASN and rDNS lookups in parallel
    let mut rdns_results: HashMap<usize, Option<String>> = HashMap::new();

    if let Some(resolver) = resolver.as_ref() {
        let mut asn_futures = FuturesUnordered::new();
        let mut rdns_futures = FuturesUnordered::new();

        for (idx, raw_hop, ipv4_addr_opt) in &hops_to_enrich {
            // ASN lookup
            if !no_asn {
                if let Some(ipv4_addr) = ipv4_addr_opt {
                    let resolver_clone = Arc::clone(resolver);
                    let ip_to_lookup = *ipv4_addr;
                    let idx_copy = *idx;
                    asn_futures.push(async move {
                        let asn_opt = lookup_asn(ip_to_lookup, &resolver_clone).await;
                        (idx_copy, asn_opt)
                    });
                }
            }

            // Reverse DNS lookup
            if !no_rdns {
                if let Some(addr) = raw_hop.addr {
                    let resolver_clone = Arc::clone(resolver);
                    let ip_to_lookup = addr;
                    let idx_copy = *idx;
                    rdns_futures.push(async move {
                        let hostname = reverse_dns_lookup(ip_to_lookup, &resolver_clone).await;
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
    }

    // Determine ISP info
    let mut isp_asn: Option<String> = None;
    if !no_asn {
        // First, try to get the public IP and its ASN to identify the ISP
        if let Ok(public_ip) = get_public_ip(Some(&resolver_for_futures)).await {
            if let Some(public_asn_info) = lookup_asn(public_ip, &resolver_for_futures).await {
                if public_asn_info.asn != "N/A" {
                    isp_asn = Some(public_asn_info.asn.clone());
                }
            }
        }
    }

    // Build final classified hops
    let mut classified_hops = Vec::new();
    let mut in_isp_segment = false;

    for (idx, (_, raw_hop, ipv4_addr_opt)) in hops_to_enrich.iter().enumerate() {
        let asn_info = asn_results.get(&idx).and_then(std::clone::Clone::clone);
        let hostname = rdns_results.get(&idx).and_then(std::clone::Clone::clone);

        let segment = if let Some(ipv4_addr) = ipv4_addr_opt {
            if is_internal_ip(ipv4_addr) || is_cgnat(ipv4_addr) {
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
