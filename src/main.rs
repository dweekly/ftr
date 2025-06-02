//! ftr - Fast TraceRoute: A parallel ICMP traceroute implementation with ASN lookup.
//!
//! This crate provides a high-performance traceroute tool that uses parallel
//! probing to significantly reduce scan time compared to traditional sequential
//! implementations. It includes automatic ASN (Autonomous System Number) lookups
//! and intelligent hop classification.

use anyhow::{bail, Context, Result};
use clap::Parser;
use futures::stream::{FuturesUnordered, StreamExt};
use hickory_resolver::config::ResolverConfig;
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::TokioResolver;
use ipnet::Ipv4Net;
use pnet::packet::icmp::echo_request::MutableEchoRequestPacket;
use pnet::packet::icmp::{echo_reply, IcmpPacket, IcmpTypes};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::Packet;
use pnet::util::checksum as pnet_checksum;
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashMap;
use std::mem::MaybeUninit;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::time::timeout as tokio_timeout;

/// The size of the payload to send with ICMP Echo Requests.
const ICMP_ECHO_PAYLOAD_SIZE: usize = 16;
/// Standard IPv4 header length in bytes, assuming no options.
const IPV4_HEADER_MIN_LEN_BYTES: usize = 20;
/// Standard ICMP header length in bytes for messages like Time Exceeded or Destination Unreachable.
const ICMP_ERROR_HEADER_LEN_BYTES: usize = 8;
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
}

/// Represents ASN information for an IP address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsnInfo {
    pub asn: String,
    pub prefix: String,
    pub country_code: String,
    pub registry: String,
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
enum HopSegment {
    Lan,
    Isp,
    Beyond,
    Unknown,
}

/// Enriched hop information including ASN and segment classification.
#[derive(Debug, Clone)]
struct ClassifiedHopInfo {
    ttl: u8,
    addr: Option<IpAddr>,
    rtt: Option<Duration>,
    asn_info: Option<AsnInfo>,
    segment: HopSegment,
}

/// Looks up ASN information for a given IPv4 address using Team Cymru's service.
/// Uses aggressive caching based on CIDR prefixes to minimize redundant lookups.
async fn lookup_asn(ip: Ipv4Addr, resolver: &TokioResolver) -> Option<AsnInfo> {
    if ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_unspecified()
    {
        let name = if ip.is_loopback() {
            "Loopback"
        } else if ip.is_private() {
            "Private Network"
        } else {
            "Special Use"
        }
        .to_string();
        return Some(AsnInfo {
            asn: "N/A".to_string(),
            prefix: ip.to_string() + "/32",
            country_code: "N/A".to_string(),
            registry: "N/A".to_string(),
            name,
        });
    }

    // Check cache first - look for any CIDR that contains this IP
    {
        let cache = ASN_CACHE.lock().unwrap();
        for (network, asn_info) in cache.iter() {
            if network.contains(&ip) {
                return Some(asn_info.clone());
            }
        }
    }

    let octets = ip.octets();
    let cymru_origin_query = format!(
        "{}.{}.{}.{}.origin.asn.cymru.com.",
        octets[3], octets[2], octets[1], octets[0]
    );

    match resolver.txt_lookup(cymru_origin_query.clone()).await {
        Ok(txt_lookup) => {
            if let Some(txt_data) = txt_lookup.iter().next() {
                let record_str = txt_data
                    .iter()
                    .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
                    .collect::<String>();
                let parts: Vec<&str> = record_str.split('|').map(|s| s.trim()).collect();
                if parts.len() >= 4 {
                    let asn_num_str = parts[0].to_string();
                    let prefix_str = parts[1].to_string();
                    let mut as_name = "N/A".to_string();

                    if asn_num_str.chars().all(char::is_numeric) && !asn_num_str.is_empty() {
                        let as_name_query = format!("AS{}.asn.cymru.com.", asn_num_str);
                        if let Ok(name_lookup) = resolver.txt_lookup(as_name_query).await {
                            if let Some(name_txt_data) = name_lookup.iter().next() {
                                let name_record_str = name_txt_data
                                    .iter()
                                    .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
                                    .collect::<String>();
                                let name_parts: Vec<&str> =
                                    name_record_str.split('|').map(|s| s.trim()).collect();
                                if let Some(name_field) = name_parts.last() {
                                    as_name = name_field.to_string();
                                }
                            }
                        }
                    }

                    let asn_info = AsnInfo {
                        asn: asn_num_str,
                        prefix: prefix_str.clone(),
                        country_code: parts[2].to_string(),
                        registry: parts[3].to_string(),
                        name: as_name,
                    };

                    // Cache the result using the CIDR prefix
                    if let Ok(network) = prefix_str.parse::<Ipv4Net>() {
                        let mut cache = ASN_CACHE.lock().unwrap();
                        cache.insert(network, asn_info.clone());
                    }

                    return Some(asn_info);
                }
            }
            None
        }
        Err(_) => None,
    }
}

/// Information about a probe that has been sent and is awaiting a reply.
#[derive(Debug, Clone, Copy)]
struct SentProbe {
    ttl: u8,
    sent_at: Instant,
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

    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4))
        .context("Failed to create ICMP DGRAM socket.")?;
    let bind_addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0);
    socket
        .bind(&bind_addr.into())
        .context("Failed to bind ICMP socket.")?;
    socket.set_read_timeout(Some(Duration::from_millis(100)))?;

    let raw_results_map: Arc<Mutex<HashMap<u8, RawHopInfo>>> = Arc::new(Mutex::new(HashMap::new()));
    let active_probes: Arc<Mutex<HashMap<u16, SentProbe>>> = Arc::new(Mutex::new(HashMap::new()));
    let destination_reached = Arc::new(Mutex::new(false));
    let probes_sent_count = Arc::new(Mutex::new(0u8));

    let socket_arc = Arc::new(socket);

    let recv_socket_clone = Arc::clone(&socket_arc);
    let results_clone_recv = Arc::clone(&raw_results_map); // Note: using RawHopInfo
    let active_probes_clone_recv = Arc::clone(&active_probes);
    let destination_reached_clone_recv = Arc::clone(&destination_reached);
    let actual_target_ip_for_receiver = target_ipv4;

    let receiver_handle = tokio::spawn(async move {
        let mut recv_buf = [MaybeUninit::uninit(); 1500];
        let receiver_start_time = Instant::now();

        loop {
            let (dest_reached, active_empty) = {
                let dr_guard = destination_reached_clone_recv.lock().unwrap();
                let ap_guard = active_probes_clone_recv.lock().unwrap();
                (*dr_guard, ap_guard.is_empty())
            };
            if dest_reached && active_empty {
                break;
            }

            if receiver_start_time.elapsed() > Duration::from_millis(args.overall_timeout_ms + 1000)
            {
                break;
            }

            match recv_socket_clone.recv_from(&mut recv_buf) {
                Ok((size, socket_addr)) => {
                    let received_from_ip = match socket_addr.as_socket_ipv4() {
                        Some(s) => IpAddr::V4(*s.ip()),
                        None => continue,
                    };
                    let reception_time = Instant::now();
                    let initialized_part: &[MaybeUninit<u8>] = &recv_buf[..size];
                    let packet_data: &[u8] =
                        unsafe { &*(initialized_part as *const [MaybeUninit<u8>] as *const [u8]) };

                    let outer_ipv4_packet = match Ipv4Packet::new(packet_data) {
                        Some(p) => p,
                        None => continue,
                    };
                    let icmp_data_from_outer_ip = outer_ipv4_packet.payload();
                    let icmp_packet_for_type_check = match IcmpPacket::new(icmp_data_from_outer_ip)
                    {
                        Some(p) => p,
                        None => continue,
                    };

                    let mut matched_probe_opt: Option<SentProbe> = None;
                    let original_datagram_bytes: &[u8] =
                        if icmp_data_from_outer_ip.len() >= ICMP_ERROR_HEADER_LEN_BYTES {
                            &icmp_data_from_outer_ip[ICMP_ERROR_HEADER_LEN_BYTES..]
                        } else {
                            continue;
                        };

                    match icmp_packet_for_type_check.get_icmp_type() {
                        IcmpTypes::TimeExceeded | IcmpTypes::DestinationUnreachable => {
                            let icmp_type = icmp_packet_for_type_check.get_icmp_type();
                            if original_datagram_bytes.len() < IPV4_HEADER_MIN_LEN_BYTES {
                                continue;
                            }
                            let inner_ip_packet = match Ipv4Packet::new(original_datagram_bytes) {
                                Some(p) => p,
                                None => continue,
                            };
                            let original_icmp_echo_bytes = inner_ip_packet.payload();
                            if original_icmp_echo_bytes.len() < 8 {
                                continue;
                            }

                            let original_type_val = original_icmp_echo_bytes[0];
                            let original_id = u16::from_be_bytes([
                                original_icmp_echo_bytes[4],
                                original_icmp_echo_bytes[5],
                            ]);
                            let original_seq = u16::from_be_bytes([
                                original_icmp_echo_bytes[6],
                                original_icmp_echo_bytes[7],
                            ]);

                            if original_type_val == IcmpTypes::EchoRequest.0
                                && original_id == icmp_identifier
                            {
                                matched_probe_opt = active_probes_clone_recv
                                    .lock()
                                    .unwrap()
                                    .remove(&original_seq);
                                if matched_probe_opt.is_some()
                                    && icmp_type == IcmpTypes::DestinationUnreachable
                                    && received_from_ip == IpAddr::V4(actual_target_ip_for_receiver)
                                {
                                    *destination_reached_clone_recv.lock().unwrap() = true;
                                }
                            }
                        }
                        IcmpTypes::EchoReply => {
                            if let Some(echo_reply_pkt) = echo_reply::EchoReplyPacket::new(
                                icmp_packet_for_type_check.packet(),
                            ) {
                                if echo_reply_pkt.get_identifier() == icmp_identifier {
                                    matched_probe_opt = active_probes_clone_recv
                                        .lock()
                                        .unwrap()
                                        .remove(&echo_reply_pkt.get_sequence_number());
                                    if matched_probe_opt.is_some() {
                                        *destination_reached_clone_recv.lock().unwrap() = true;
                                    }
                                }
                            }
                        }
                        _ => {}
                    }

                    if let Some(probe_info) = matched_probe_opt {
                        let rtt = reception_time.duration_since(probe_info.sent_at);
                        let hop_info = RawHopInfo {
                            // Store RawHopInfo
                            ttl: probe_info.ttl,
                            addr: Some(received_from_ip),
                            rtt: Some(rtt),
                        };
                        results_clone_recv
                            .lock()
                            .unwrap()
                            .insert(probe_info.ttl, hop_info);
                    }
                }
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut => {}
                Err(e) => {
                    eprintln!("[Receiver] Socket recv error: {}. Terminating.", e);
                    break;
                }
            }
            tokio::task::yield_now().await;
        }
    });

    let mut send_tasks = Vec::new();
    for ttl_val in args.start_ttl..=effective_max_hops {
        let task_socket_arc = Arc::clone(&socket_arc);
        let task_active_probes = Arc::clone(&active_probes);
        let task_probes_sent_count = Arc::clone(&probes_sent_count);

        let sender_task = tokio::spawn(async move {
            let sequence_number = ttl_val as u16;
            if let Err(_e) = task_socket_arc.set_ttl(ttl_val as u32) {
                return;
            }
            let mut icmp_buf =
                vec![0u8; MutableEchoRequestPacket::minimum_packet_size() + ICMP_ECHO_PAYLOAD_SIZE];
            let mut echo_req_packet = MutableEchoRequestPacket::new(&mut icmp_buf).unwrap();
            echo_req_packet.set_icmp_type(IcmpTypes::EchoRequest);
            echo_req_packet.set_icmp_code(pnet::packet::icmp::IcmpCode(0));
            echo_req_packet.set_identifier(icmp_identifier);
            echo_req_packet.set_sequence_number(sequence_number);
            let payload_data_source = (icmp_identifier as u32) << 16 | (sequence_number as u32);
            let payload_bytes = payload_data_source.to_be_bytes();
            let mut final_payload = vec![0u8; ICMP_ECHO_PAYLOAD_SIZE];
            let bytes_to_copy = payload_bytes.len().min(ICMP_ECHO_PAYLOAD_SIZE);
            final_payload[..bytes_to_copy].copy_from_slice(&payload_bytes[..bytes_to_copy]);
            echo_req_packet.set_payload(&final_payload);
            let checksum = pnet_checksum(echo_req_packet.packet(), 1);
            echo_req_packet.set_checksum(checksum);
            let target_saddr = SocketAddr::V4(SocketAddrV4::new(target_ipv4, 0));
            let sent_at = Instant::now();
            match task_socket_arc.send_to(echo_req_packet.packet(), &target_saddr.into()) {
                Ok(_) => {
                    task_active_probes.lock().unwrap().insert(
                        sequence_number,
                        SentProbe {
                            ttl: ttl_val,
                            sent_at,
                        },
                    );
                    *task_probes_sent_count.lock().unwrap() += 1;
                }
                Err(_e) => {}
            }
        });
        send_tasks.push(sender_task);
        if args.send_launch_interval_ms > 0 {
            tokio::time::sleep(Duration::from_millis(args.send_launch_interval_ms)).await;
        }
    }

    for task in send_tasks {
        let _ = task.await;
    }

    let overall_start_time = Instant::now();
    loop {
        let dest_reached = *destination_reached.lock().unwrap();
        let active_empty = active_probes.lock().unwrap().is_empty();
        let total_probes_expected = *probes_sent_count.lock().unwrap();
        let results_count = raw_results_map.lock().unwrap().len();
        if (dest_reached && active_empty)
            || (results_count >= total_probes_expected as usize
                && total_probes_expected > 0
                && active_empty)
        {
            break;
        }
        if overall_start_time.elapsed() > Duration::from_millis(args.overall_timeout_ms) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    {
        // Final check for timed-out active probes
        let mut active_probes_guard = active_probes.lock().unwrap();
        let mut results_guard = raw_results_map.lock().unwrap(); // Using RawHopInfo
        let now = Instant::now();
        active_probes_guard.retain(|_seq, probe| {
            if now.duration_since(probe.sent_at) > Duration::from_millis(args.probe_timeout_ms) {
                results_guard.entry(probe.ttl).or_insert(RawHopInfo {
                    ttl: probe.ttl,
                    addr: None,
                    rtt: None,
                });
                false
            } else {
                true
            }
        });
    }

    // --- Phase 2: Post-Processing - ASN Lookup and Classification ---
    if !args.no_enrich {
        println!("\nPerforming ASN lookups and classifying segments...");
        let final_classified_hops = process_hops_for_asn_and_classification(
            args.start_ttl,
            effective_max_hops,
            raw_results_map, // Pass the map with RawHopInfo
            args.no_enrich,  // Though already checked, pass for consistency
        )
        .await?;

        // --- Phase 3: Printing Final Classified Results ---
        let destination_ip = IpAddr::V4(target_ipv4);
        for hop_info in &final_classified_hops {
            print_classified_hop_info(hop_info);
            // Stop printing once we reach the destination
            if hop_info.addr == Some(destination_ip) {
                break;
            }
        }
    } else {
        // Print raw results if --no-enrich
        println!("\nTraceroute path (raw):");
        let destination_ip = IpAddr::V4(target_ipv4);
        for ttl_val in args.start_ttl..=effective_max_hops {
            let results_guard = raw_results_map.lock().unwrap();
            if let Some(raw_hop) = results_guard.get(&ttl_val) {
                print_raw_hop_info(raw_hop);
                // Stop printing once we reach the destination
                if raw_hop.addr == Some(destination_ip) {
                    break;
                }
            } else {
                print_raw_hop_info(&RawHopInfo {
                    ttl: ttl_val,
                    addr: None,
                    rtt: None,
                });
            }
        }
    }

    let _ = tokio_timeout(Duration::from_millis(500), receiver_handle).await;
    Ok(())
}

/// Performs ASN lookups and classifies hops into LAN, ISP, or BEYOND.
async fn process_hops_for_asn_and_classification(
    start_ttl: u8,
    max_ttl: u8,
    raw_results_map_arc: Arc<Mutex<HashMap<u8, RawHopInfo>>>,
    no_asn: bool,
) -> Result<Vec<ClassifiedHopInfo>> {
    let collected_hops_raw: Vec<RawHopInfo> = {
        let guard = raw_results_map_arc.lock().unwrap();
        (start_ttl..=max_ttl)
            .map(|ttl| {
                guard.get(&ttl).cloned().unwrap_or(RawHopInfo {
                    ttl,
                    addr: None,
                    rtt: None,
                })
            })
            .collect()
    };

    // We'll store (original_index, raw_hop_data, Option<Ipv4Addr> for lookup)
    let hops_to_enrich: Vec<(usize, RawHopInfo, Option<Ipv4Addr>)> = collected_hops_raw
        .into_iter()
        .enumerate()
        .map(|(idx, raw_hop)| {
            let ipv4_addr_opt = match raw_hop.addr {
                Some(IpAddr::V4(v4_addr)) => Some(v4_addr),
                _ => None,
            };
            (idx, raw_hop, ipv4_addr_opt)
        })
        .collect();

    let mut asn_info_results: HashMap<usize, Option<AsnInfo>> = HashMap::new();

    if !no_asn {
        let resolver_instance = TokioResolver::builder_with_config(
            ResolverConfig::default(),
            TokioConnectionProvider::default(),
        )
        .build();

        let resolver = Arc::new(resolver_instance);

        let mut asn_lookup_futures = FuturesUnordered::new();

        for (idx, _raw_hop, ipv4_addr_opt) in &hops_to_enrich {
            if let Some(ipv4_addr) = ipv4_addr_opt {
                let resolver_clone = Arc::clone(&resolver);
                let ip_to_lookup = *ipv4_addr;
                asn_lookup_futures.push(async move {
                    let asn_opt = lookup_asn(ip_to_lookup, &resolver_clone).await;
                    (*idx, asn_opt)
                });
            }
        }
        while let Some((idx, asn_opt)) = asn_lookup_futures.next().await {
            asn_info_results.insert(idx, asn_opt);
        }
    }

    // Classify Segments with improved ISP detection
    let mut classified_hops_final = Vec::new();
    let mut on_lan = true;
    let mut isp_asns: std::collections::HashSet<String> = std::collections::HashSet::new();

    for (idx, raw_hop, _ipv4_addr_opt) in hops_to_enrich {
        let current_asn_info = asn_info_results.remove(&idx).flatten();
        let mut segment = HopSegment::Unknown;

        if let Some(ip_addr) = raw_hop.addr {
            let ipv4_addr = match ip_addr {
                IpAddr::V4(v4) => v4,
                _ => Ipv4Addr::UNSPECIFIED,
            };
            if ipv4_addr.is_loopback() || ipv4_addr.is_private() {
                segment = HopSegment::Lan;
                if !on_lan {
                    on_lan = true;
                    // Don't clear ISP ASNs when returning to LAN - we might go back to public
                }
            } else {
                // Public IP
                on_lan = false;
                if let Some(ref local_asn_info_ref) = current_asn_info {
                    if local_asn_info_ref.asn != "N/A" {
                        // Check if this ASN is already known as an ISP ASN
                        if isp_asns.contains(&local_asn_info_ref.asn) {
                            segment = HopSegment::Isp;
                        } else if isp_asns.is_empty() {
                            // First public IP encountered - this is likely the ISP
                            segment = HopSegment::Isp;
                            isp_asns.insert(local_asn_info_ref.asn.clone());
                        } else {
                            // Different ASN from known ISP ASNs - this is beyond ISP
                            segment = HopSegment::Beyond;
                        }
                    } else {
                        segment = HopSegment::Beyond;
                    }
                } else {
                    segment = HopSegment::Beyond;
                }
            }
        }

        classified_hops_final.push(ClassifiedHopInfo {
            ttl: raw_hop.ttl,
            addr: raw_hop.addr,
            rtt: raw_hop.rtt,
            asn_info: current_asn_info,
            segment,
        });
    }
    Ok(classified_hops_final)
}

/// Prints enriched hop information including ASN and segment.
fn print_classified_hop_info(hop_info: &ClassifiedHopInfo) {
    let segment_str = format!("[{:<6}]", format!("{:?}", hop_info.segment).to_uppercase());
    if let Some(addr) = hop_info.addr {
        let rtt_str = hop_info.rtt.map_or_else(
            || String::from("*       "),
            |rtt| format!("{:>7.3} ms", rtt.as_secs_f64() * 1000.0),
        );
        let asn_display = if let Some(info) = &hop_info.asn_info {
            if info.asn == "N/A" {
                format!("({})", info.name)
            } else {
                let mut as_name_truncated = info.name.clone();
                const MAX_AS_NAME_LEN: usize = 25;
                if as_name_truncated.len() > MAX_AS_NAME_LEN {
                    as_name_truncated.truncate(MAX_AS_NAME_LEN - 3);
                    as_name_truncated.push_str("...");
                }
                format!("(AS{} - {})", info.asn, as_name_truncated)
            }
        } else {
            String::new()
        };
        println!(
            "{:2} {} {} {}  {}",
            hop_info.ttl, segment_str, addr, asn_display, rtt_str
        );
    } else {
        println!("{:2} {} * * *", hop_info.ttl, segment_str);
    }
    std::io::Write::flush(&mut std::io::stdout()).ok();
}

/// Prints raw hop information (without ASN/segment).
fn print_raw_hop_info(raw_hop_info: &RawHopInfo) {
    if let Some(addr) = raw_hop_info.addr {
        let rtt_str = raw_hop_info.rtt.map_or_else(
            || String::from("*"),
            |rtt| format!("{:>7.3} ms", rtt.as_secs_f64() * 1000.0),
        );
        println!("{:2}  {}  {}", raw_hop_info.ttl, addr, rtt_str);
    } else {
        println!("{:2}  * * *", raw_hop_info.ttl);
    }
    std::io::Write::flush(&mut std::io::stdout()).ok();
}

async fn resolve_host(host: &str) -> Result<Ipv4Addr> {
    if let Ok(ipv4_addr) = host.parse::<Ipv4Addr>() {
        return Ok(ipv4_addr);
    }
    if let Ok(ip_addr) = host.parse::<IpAddr>() {
        if let IpAddr::V4(ipv4_addr) = ip_addr {
            return Ok(ipv4_addr);
        } else {
            bail!(
                "IPv6 addresses ({}) are not supported by this version.",
                host
            );
        }
    }
    let addresses = tokio::net::lookup_host(format!("{}:0", host))
        .await
        .with_context(|| format!("Failed to resolve host: {}", host))?;
    for addr in addresses {
        if let SocketAddr::V4(sock_addr_v4) = addr {
            return Ok(*sock_addr_v4.ip());
        }
    }
    bail!("No IPv4 address found for host: {}", host)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[tokio::test]
    async fn test_resolve_host_ipv4_direct() {
        let ip = resolve_host("192.168.1.1").await.unwrap();
        assert_eq!(ip, Ipv4Addr::new(192, 168, 1, 1));
    }

    #[tokio::test]
    async fn test_resolve_host_ipv6_direct_unsupported() {
        let result = resolve_host("::1").await;
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("IPv6"));
    }

    #[tokio::test]
    async fn test_resolve_host_valid_hostname() {
        // Using localhost which should always resolve
        let result = resolve_host("localhost").await;
        assert!(result.is_ok());
        let ip = result.unwrap();
        assert!(ip.is_loopback());
    }

    #[tokio::test]
    async fn test_resolve_host_invalid_hostname() {
        let result = resolve_host("this-host-definitely-does-not-exist.invalid").await;
        assert!(result.is_err());
    }

    #[test]
    fn test_clap_args_parsing_basic() {
        let args = Args::try_parse_from(&["ftr", "example.com"]).unwrap();
        assert_eq!(args.host, "example.com");
        assert_eq!(args.start_ttl, 1);
        assert_eq!(args.max_hops, 30);
        assert_eq!(args.probe_timeout_ms, 1000);
        assert_eq!(args.send_launch_interval_ms, 5);
        assert_eq!(args.overall_timeout_ms, DEFAULT_OVERALL_TIMEOUT_MS);
        assert!(!args.no_enrich);
    }

    #[test]
    fn test_clap_args_no_enrich() {
        let args = Args::try_parse_from(&["ftr", "example.com", "--no-enrich"]).unwrap();
        assert!(args.no_enrich);
    }

    #[test]
    fn test_clap_args_custom_values() {
        let args = Args::try_parse_from(&[
            "ftr",
            "example.com",
            "-s",
            "5",
            "-m",
            "20",
            "--probe-timeout-ms",
            "500",
            "-i",
            "10",
            "-W",
            "5000",
        ])
        .unwrap();
        assert_eq!(args.start_ttl, 5);
        assert_eq!(args.max_hops, 20);
        assert_eq!(args.probe_timeout_ms, 500);
        assert_eq!(args.send_launch_interval_ms, 10);
        assert_eq!(args.overall_timeout_ms, 5000);
    }

    #[test]
    fn test_asn_info_equality() {
        let asn1 = AsnInfo {
            asn: "12345".to_string(),
            prefix: "192.168.0.0/16".to_string(),
            country_code: "US".to_string(),
            registry: "arin".to_string(),
            name: "Example ISP".to_string(),
        };
        let asn2 = asn1.clone();
        assert_eq!(asn1, asn2);
    }

    #[test]
    fn test_hop_segment_classification() {
        let segments = vec![
            HopSegment::Lan,
            HopSegment::Isp,
            HopSegment::Beyond,
            HopSegment::Unknown,
        ];

        // Test Debug trait implementation
        for segment in &segments {
            let debug_str = format!("{:?}", segment);
            assert!(!debug_str.is_empty());
        }

        // Test equality
        assert_eq!(HopSegment::Lan, HopSegment::Lan);
        assert_ne!(HopSegment::Lan, HopSegment::Isp);
    }

    #[tokio::test]
    async fn test_lookup_asn_private_addresses() {
        let resolver = TokioResolver::builder_with_config(
            ResolverConfig::default(),
            TokioConnectionProvider::default(),
        )
        .build();

        // Test private IP
        let result = lookup_asn(Ipv4Addr::new(192, 168, 1, 1), &resolver).await;
        assert!(result.is_some());
        let asn_info = result.unwrap();
        assert_eq!(asn_info.asn, "N/A");
        assert_eq!(asn_info.name, "Private Network");

        // Test loopback
        let result = lookup_asn(Ipv4Addr::new(127, 0, 0, 1), &resolver).await;
        assert!(result.is_some());
        let asn_info = result.unwrap();
        assert_eq!(asn_info.asn, "N/A");
        assert_eq!(asn_info.name, "Loopback");
    }

    #[test]
    fn test_raw_hop_info_creation() {
        let hop = RawHopInfo {
            ttl: 5,
            addr: Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
            rtt: Some(Duration::from_millis(10)),
        };
        assert_eq!(hop.ttl, 5);
        assert!(hop.addr.is_some());
        assert!(hop.rtt.is_some());
    }

    #[test]
    fn test_classified_hop_info_creation() {
        let hop = ClassifiedHopInfo {
            ttl: 3,
            addr: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            rtt: Some(Duration::from_millis(5)),
            asn_info: None,
            segment: HopSegment::Lan,
        };
        assert_eq!(hop.ttl, 3);
        assert_eq!(hop.segment, HopSegment::Lan);
    }

    #[test]
    fn test_ipv4_net_parsing() {
        let network_str = "192.168.0.0/16";
        let network = Ipv4Net::from_str(network_str).unwrap();

        // Test that IPs in the network are contained
        assert!(network.contains(&Ipv4Addr::new(192, 168, 1, 1)));
        assert!(network.contains(&Ipv4Addr::new(192, 168, 255, 255)));

        // Test that IPs outside the network are not contained
        assert!(!network.contains(&Ipv4Addr::new(192, 169, 1, 1)));
        assert!(!network.contains(&Ipv4Addr::new(10, 0, 0, 1)));
    }

    #[test]
    fn test_sent_probe_structure() {
        let probe = SentProbe {
            ttl: 10,
            sent_at: Instant::now(),
        };
        assert_eq!(probe.ttl, 10);

        // Test that time progresses
        std::thread::sleep(Duration::from_millis(1));
        let elapsed = Instant::now().duration_since(probe.sent_at);
        assert!(elapsed > Duration::ZERO);
    }
}
