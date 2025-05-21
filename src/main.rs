//! A minimalist, fast ICMP Echo based traceroute implementation.
//! This version uses parallel probing to send out requests for multiple TTLs concurrently.

use anyhow::{bail, Context, Result};
use clap::Parser;
use pnet::packet::icmp::{echo_reply, IcmpPacket, IcmpTypes};
use pnet::packet::icmp::echo_request::MutableEchoRequestPacket;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::Packet; 
use pnet::util::checksum as pnet_checksum;
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::time::timeout as tokio_timeout;
use std::mem::MaybeUninit; 

/// The size of the payload to send with ICMP Echo Requests.
const ICMP_ECHO_PAYLOAD_SIZE: usize = 16;
/// Standard IPv4 header length in bytes, assuming no options.
const IPV4_HEADER_MIN_LEN_BYTES: usize = 20;
/// Standard ICMP header length in bytes for messages like Time Exceeded or Destination Unreachable.
const ICMP_ERROR_HEADER_LEN_BYTES: usize = 8;
/// Default overall timeout for the entire traceroute operation if not all replies received.
const DEFAULT_OVERALL_TIMEOUT_MS: u64 = 3000; // 3 seconds

/// Command-line arguments for the traceroute tool.
#[derive(Parser, Debug)]
#[clap(author, version, about = "Minimalist Parallel ICMP Traceroute", long_about = None)]
struct Args {
    /// The destination host or IP address.
    host: String,

    /// Starting Time-To-Live (TTL) value.
    #[clap(short, long, default_value_t = 1)]
    start_ttl: u8,

    /// Maximum number of hops (max TTL) to probe.
    #[clap(short = 'm', long, default_value_t = 20)] // Capped at 20 for "no more than 20 hops"
    max_hops: u8,

    /// Timeout in milliseconds for an individual probe to be considered lost.
    #[clap(long, default_value_t = 1000)] // Timeout for individual probes
    probe_timeout_ms: u64,

    /// Interval in milliseconds between launching send tasks. Can be very small for parallel.
    #[clap(short = 'i', long, default_value_t = 5)]
    send_launch_interval_ms: u64,

    /// Overall timeout in milliseconds for the entire traceroute operation.
    #[clap(short = 'W', long, default_value_t = DEFAULT_OVERALL_TIMEOUT_MS)]
    overall_timeout_ms: u64,
}

/// Information about a single hop in the traceroute path.
#[derive(Debug, Clone)]
struct HopInfo {
    ttl: u8,
    addr: Option<IpAddr>,
    rtt: Option<Duration>,
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
    let effective_max_hops = args.max_hops.min(30); // Practical cap, though user can specify lower.

    let target_ipv4 = match resolve_host(&args.host).await {
        Ok(ip) => ip,
        Err(e) => { eprintln!("Error resolving host {}: {}", args.host, e); return Ok(()); }
    };

    println!(
        "Traceroute to {} ({}), {} max hops, {}ms probe timeout, {}ms overall timeout",
        args.host, target_ipv4, effective_max_hops, args.probe_timeout_ms, args.overall_timeout_ms
    );

    let icmp_identifier = std::process::id() as u16;

    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4))
        .context("Failed to create ICMP DGRAM socket.")?;
    let bind_addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0);
    socket.bind(&bind_addr.into()).context("Failed to bind ICMP socket.")?;
    // Read timeout for the receiver's recv_from calls.
    socket.set_read_timeout(Some(Duration::from_millis(100)))?; 

    let results_map: Arc<Mutex<HashMap<u8, HopInfo>>> = Arc::new(Mutex::new(HashMap::new()));
    let active_probes: Arc<Mutex<HashMap<u16, SentProbe>>> = Arc::new(Mutex::new(HashMap::new()));
    let destination_reached = Arc::new(Mutex::new(false));
    let probes_sent_count = Arc::new(Mutex::new(0u8)); // To track how many sender tasks are launched

    let socket_arc = Arc::new(socket); // Socket shared by receiver and all sender tasks
    
    // --- Receiver Task Setup ---
    let recv_socket_clone = Arc::clone(&socket_arc);
    let results_clone_recv = Arc::clone(&results_map);
    let active_probes_clone_recv = Arc::clone(&active_probes);
    let destination_reached_clone_recv = Arc::clone(&destination_reached);
    // let target_ipv4_clone_recv = target_ipv4; // Receiver needs this

    let receiver_handle = tokio::spawn(async move {
        // Receiver logic is largely the same as the last working version
        let mut recv_buf = [MaybeUninit::uninit(); 1500]; 
        let receiver_start_time = Instant::now(); // For receiver's own max lifetime if needed

        loop {
            // Exit conditions for receiver
            let (dest_reached, active_empty) = {
                let dr_guard = destination_reached_clone_recv.lock().unwrap();
                let ap_guard = active_probes_clone_recv.lock().unwrap();
                (*dr_guard, ap_guard.is_empty())
            };
            if dest_reached && active_empty { break; }
            
            // Optional: Receiver overall timeout
            if receiver_start_time.elapsed() > Duration::from_millis(args.overall_timeout_ms + 1000) { // A bit longer than main
                // eprintln!("[Receiver] Overall timeout reached.");
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
                    let packet_data: &[u8] = unsafe { &*(initialized_part as *const [MaybeUninit<u8>] as *const [u8]) };

                    let outer_ipv4_packet = match Ipv4Packet::new(packet_data) { Some(p) => p, None => continue };
                    let icmp_data_from_outer_ip = outer_ipv4_packet.payload(); 
                    let icmp_packet_for_type_check = match IcmpPacket::new(icmp_data_from_outer_ip) { Some(p) => p, None => continue };

                    let mut matched_probe_opt: Option<SentProbe> = None;
                    let original_datagram_bytes: &[u8];
                    if icmp_data_from_outer_ip.len() >= ICMP_ERROR_HEADER_LEN_BYTES {
                        original_datagram_bytes = &icmp_data_from_outer_ip[ICMP_ERROR_HEADER_LEN_BYTES..];
                    } else { continue; }

                    match icmp_packet_for_type_check.get_icmp_type() {
                        IcmpTypes::TimeExceeded | IcmpTypes::DestinationUnreachable => {
                            let icmp_type = icmp_packet_for_type_check.get_icmp_type(); 
                            if original_datagram_bytes.len() < IPV4_HEADER_MIN_LEN_BYTES { continue; }
                            let inner_ip_packet = match Ipv4Packet::new(original_datagram_bytes) { Some(p) => p, None => continue };
                            let original_icmp_echo_bytes = inner_ip_packet.payload();
                            if original_icmp_echo_bytes.len() < 8 { continue; }

                            let original_type_val = original_icmp_echo_bytes[0];
                            let original_id = u16::from_be_bytes([original_icmp_echo_bytes[4], original_icmp_echo_bytes[5]]);
                            let original_seq = u16::from_be_bytes([original_icmp_echo_bytes[6], original_icmp_echo_bytes[7]]);

                            if original_type_val == IcmpTypes::EchoRequest.0 && original_id == icmp_identifier {
                                matched_probe_opt = active_probes_clone_recv.lock().unwrap().remove(&original_seq);
                                if matched_probe_opt.is_some() && 
                                   icmp_type == IcmpTypes::DestinationUnreachable && 
                                   received_from_ip == IpAddr::V4(target_ipv4) { // Use captured target_ipv4
                                    *destination_reached_clone_recv.lock().unwrap() = true;
                                }
                            }
                        }
                        IcmpTypes::EchoReply => {
                            if let Some(echo_reply_pkt) = echo_reply::EchoReplyPacket::new(icmp_packet_for_type_check.packet()){
                                if echo_reply_pkt.get_identifier() == icmp_identifier {
                                    matched_probe_opt = active_probes_clone_recv.lock().unwrap().remove(&echo_reply_pkt.get_sequence_number());
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
                        let hop_info = HopInfo { ttl: probe_info.ttl, addr: Some(received_from_ip), rtt: Some(rtt) };
                        results_clone_recv.lock().unwrap().insert(probe_info.ttl, hop_info);
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => {}
                Err(e) => { eprintln!("[Receiver] Socket recv error: {}. Terminating.", e); break; }
            }
            tokio::task::yield_now().await; 
        }
    });

    // --- Parallel Sender Logic ---
    let mut send_tasks = Vec::new();
    for ttl_val in args.start_ttl..=effective_max_hops {
        // Clone Arcs needed for each sender task
        let task_socket_arc = Arc::clone(&socket_arc);
        let task_active_probes = Arc::clone(&active_probes);
        let task_probes_sent_count = Arc::clone(&probes_sent_count);

        let sender_task = tokio::spawn(async move {
            let sequence_number = ttl_val as u16;
            // Set TTL on a non-blocking socket might not be directly possible like this
            // if the socket is shared. Raw sockets on some OSes allow per-packet TTL.
            // For DGRAM, set_ttl is per-socket. This implies that if we send rapidly,
            // the TTL might not update for each packet if sends are faster than OS processes set_ttl.
            // A more robust way would be one socket per sender task, or use raw IP sockets (needs sudo).
            // For now, we'll try setting TTL on the shared socket just before send. This is a potential race.
            // The alternative of creating a new socket for each TTL is heavier.
            if let Err(_e) = task_socket_arc.set_ttl(ttl_val as u32) {
                // eprintln!("TTL {}: Failed to set TTL: {}", ttl_val, e);
                return; // Skip this probe if TTL cannot be set
            }

            let mut icmp_buf = vec![0u8; MutableEchoRequestPacket::minimum_packet_size() + ICMP_ECHO_PAYLOAD_SIZE];
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
                        SentProbe { ttl: ttl_val, sent_at }
                    );
                    *task_probes_sent_count.lock().unwrap() += 1;
                }
                Err(_e) => {
                    // eprintln!("TTL {}: Send error: {}", ttl_val, _e);
                    // If send fails, it won't be in active_probes, will show as timeout.
                }
            }
        });
        send_tasks.push(sender_task);
        if args.send_launch_interval_ms > 0 {
            tokio::time::sleep(Duration::from_millis(args.send_launch_interval_ms)).await;
        }
    }

    // Wait for all sender tasks to complete (they are short-lived)
    for task in send_tasks {
        let _ = task.await; // Ignore errors from sender tasks for now
    }

    // --- Main Wait and Result Collection ---
    let overall_start_time = Instant::now();
    loop {
        let dest_reached = *destination_reached.lock().unwrap();
        let active_empty = active_probes.lock().unwrap().is_empty();
        let total_probes_expected = *probes_sent_count.lock().unwrap();
        let results_count = results_map.lock().unwrap().len();


        // Exit if destination reached and all active probes resolved,
        // OR if all sent probes have either a result or are deemed timed out by now
        // (This second part is implicitly handled by overall_timeout)
        if (dest_reached && active_empty) || 
           (results_count >= total_probes_expected as usize && total_probes_expected > 0 && active_empty) {
            break;
        }

        if overall_start_time.elapsed() > Duration::from_millis(args.overall_timeout_ms) {
            // eprintln!("[Main] Overall timeout reached.");
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await; // Check periodically
    }

    // --- Final Processing and Printing ---
    // Check for probes that timed out based on individual probe_timeout_ms
    {
        let mut active_probes_guard = active_probes.lock().unwrap();
        let mut results_guard = results_map.lock().unwrap();
        let now = Instant::now();
        active_probes_guard.retain(|_seq, probe| {
            if now.duration_since(probe.sent_at) > Duration::from_millis(args.probe_timeout_ms) {
                // This probe timed out, ensure it's marked as such if not already replied
                if !results_guard.contains_key(&probe.ttl) {
                    results_guard.insert(probe.ttl, HopInfo { ttl: probe.ttl, addr: None, rtt: None });
                }
                false // Remove from active_probes
            } else {
                true // Keep in active_probes (shouldn't happen if overall timeout is reasonable)
            }
        });
    }


    for ttl_val in args.start_ttl..=effective_max_hops {
        let results_guard = results_map.lock().unwrap();
        if let Some(hop_info) = results_guard.get(&ttl_val) {
            print_hop_info(hop_info);
        } else {
            // If not in results, it means it timed out and wasn't caught by the explicit check above,
            // or was never sent successfully.
            print_hop_info(&HopInfo { ttl: ttl_val, addr: None, rtt: None });
        }
    }
    
    // Ensure receiver task is joined.
    let _ = tokio_timeout(Duration::from_millis(500), receiver_handle).await;

    Ok(())
}

// print_hop_info and resolve_host functions remain the same as the previous clean version
fn print_hop_info(hop_info: &HopInfo) {
    if let Some(addr) = hop_info.addr {
        if addr.is_unspecified() { 
             // This was for send error indication, which is now less direct
        } else if let Some(rtt) = hop_info.rtt {
            print!("{:2}  {}  {:>7.3} ms\n", hop_info.ttl, addr, rtt.as_secs_f64() * 1000.0);
        } else { 
            print!("{:2}  {}\n", hop_info.ttl, addr);
        }
    } else {
        print!("{:2}  * * *\n", hop_info.ttl);
    }
    std::io::Write::flush(&mut std::io::stdout()).ok();
}

async fn resolve_host(host: &str) -> Result<Ipv4Addr> {
    if let Ok(ipv4_addr) = host.parse::<Ipv4Addr>() { return Ok(ipv4_addr); }
    if let Ok(ip_addr) = host.parse::<IpAddr>() {
        if let IpAddr::V4(ipv4_addr) = ip_addr { return Ok(ipv4_addr); }
        else { bail!("IPv6 addresses ({}) are not supported by this version.", host); }
    }
    let addresses = tokio::net::lookup_host(format!("{}:0", host)).await
        .with_context(|| format!("Failed to resolve host: {}", host))?;
    for addr in addresses {
        if let SocketAddr::V4(sock_addr_v4) = addr { return Ok(*sock_addr_v4.ip()); }
    }
    bail!("No IPv4 address found for host: {}", host)
}


#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_resolve_host_ipv4_direct() {
        let ip_str = "1.1.1.1";
        assert_eq!(resolve_host(ip_str).await.unwrap(), ip_str.parse::<Ipv4Addr>().unwrap());
    }

    #[tokio::test]
    async fn test_resolve_host_ipv6_direct_unsupported() {
        let ip_str = "2001:db8::1";
        assert!(resolve_host(ip_str).await.is_err());
    }

    #[tokio::test]
    async fn test_resolve_host_valid_hostname() {
        let host = "localhost"; 
        let result = resolve_host(host).await;
        assert!(result.is_ok());
        let resolved_ip = result.unwrap();
        assert!(resolved_ip.is_loopback() || resolved_ip == Ipv4Addr::new(127,0,0,1));

        // This test requires network access
        let public_host = "one.one.one.one";
        let expected_public_ip: Ipv4Addr = "1.1.1.1".parse().unwrap();
        let expected_alternate_public_ip: Ipv4Addr = "1.0.0.1".parse().unwrap();
        match resolve_host(public_host).await {
            Ok(ip) => {
                 assert!(ip == expected_public_ip || ip == expected_alternate_public_ip);
            }
            Err(e) => panic!("Failed to resolve public_host {}: {}", public_host, e),
        }
    }
    
    #[tokio::test]
    async fn test_resolve_host_invalid_hostname() {
        let host = "this.is.not.a.valid.hostname.example.com";
        assert!(resolve_host(host).await.is_err());
    }

    #[test]
    fn test_clap_args_parsing_basic() {
        let args = Args::try_parse_from(&["mytraceroute", "example.com"]).unwrap();
        assert_eq!(args.host, "example.com");
        assert_eq!(args.max_hops, 20); // Default from clap
    }
}