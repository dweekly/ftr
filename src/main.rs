use anyhow::{bail, Context, Result};
use clap::Parser;
use pnet::packet::icmp::{
    echo_reply, IcmpPacket, IcmpTypes,
};
use pnet::packet::icmp::echo_request::{MutableEchoRequestPacket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::Packet; // Trait for common packet methods
use pnet::util::checksum as pnet_checksum;
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::time::timeout as tokio_timeout;
use std::mem::MaybeUninit; // For uninitialized socket buffers

/// The size of the payload to send with ICMP Echo Requests.
const ICMP_ECHO_PAYLOAD_SIZE: usize = 16;
/// Standard IPv4 header length in bytes, assuming no options.
const IPV4_HEADER_MIN_LEN_BYTES: usize = 20;
/// Standard ICMP header length in bytes for messages like Time Exceeded or Destination Unreachable
/// (Type, Code, Checksum, 4 bytes of "unused" or message-specific field).
const ICMP_ERROR_HEADER_LEN_BYTES: usize = 8;

/// Command-line arguments for the traceroute tool.
#[derive(Parser, Debug)]
#[clap(author, version, about = "Minimalist ICMP Traceroute", long_about = None)]
struct Args {
    /// The destination host or IP address.
    host: String,

    /// Starting Time-To-Live (TTL) value.
    #[clap(short, long, default_value_t = 1)]
    start_ttl: u8,

    /// Maximum number of hops (max TTL) to probe.
    #[clap(short = 'm', long, default_value_t = 30)]
    max_hops: u8,

    /// Timeout in milliseconds to wait for a reply for each hop.
    #[clap(long, default_value_t = 800)]
    hop_timeout_ms: u64,

    /// Interval in milliseconds between sending probes for successive TTLs.
    #[clap(short = 'i', long, default_value_t = 50)]
    send_interval_ms: u64,
}

/// Information about a single hop in the traceroute path.
#[derive(Debug, Clone)]
struct HopInfo {
    /// The TTL value used to reach this hop.
    ttl: u8,
    /// The IP address of the router at this hop, if a reply was received.
    addr: Option<IpAddr>,
    /// The round-trip time to this hop, if a reply was received.
    rtt: Option<Duration>,
}

/// Information about a probe that has been sent and is awaiting a reply.
#[derive(Debug, Clone, Copy)]
struct SentProbe {
    /// The TTL value of the sent probe.
    ttl: u8,
    /// The time at which the probe was sent.
    sent_at: Instant,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let target_ipv4 = match resolve_host(&args.host).await {
        Ok(ip) => ip,
        Err(e) => {
            eprintln!("Error resolving host {}: {}", args.host, e);
            return Ok(());
        }
    };

    println!(
        "Traceroute to {} ({}), {} max hops, {}ms hop timeout",
        args.host, target_ipv4, args.max_hops, args.hop_timeout_ms
    );

    let icmp_identifier = std::process::id() as u16;

    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4))
        .context("Failed to create ICMP DGRAM socket. Ensure your OS supports unprivileged ICMP DGRAM sockets.")?;
    
    let bind_addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0);
    socket.bind(&bind_addr.into())
        .context("Failed to bind ICMP socket. Another process might be using it, or permissions are insufficient.")?;
    
    socket.set_read_timeout(Some(Duration::from_millis(args.hop_timeout_ms / 4)))?;

    let results_map: Arc<Mutex<HashMap<u8, HopInfo>>> = Arc::new(Mutex::new(HashMap::new()));
    let active_probes: Arc<Mutex<HashMap<u16, SentProbe>>> = Arc::new(Mutex::new(HashMap::new()));
    let destination_reached = Arc::new(Mutex::new(false));

    let socket_arc = Arc::new(socket);
    let recv_socket_clone = Arc::clone(&socket_arc); 

    let results_clone = Arc::clone(&results_map);
    let active_probes_clone = Arc::clone(&active_probes);
    let destination_reached_clone = Arc::clone(&destination_reached);
    
    // VVV RENAMED VARIABLE FOR CAPTURE CLARITY VVV
    let actual_target_ip_for_receiver = target_ipv4; 

    let receiver_handle = tokio::spawn(async move { // actual_target_ip_for_receiver is moved in
        // Optional: eprintln!("[Receiver] Started. Our ICMP ID: {}", icmp_identifier);
        let mut recv_buf = [MaybeUninit::uninit(); 1500]; 
        
        loop {
            if *destination_reached_clone.lock().unwrap() && active_probes_clone.lock().unwrap().is_empty() {
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
                    let packet_data: &[u8] = unsafe {
                        &*(initialized_part as *const [MaybeUninit<u8>] as *const [u8])
                    };

                    let outer_ipv4_packet = match Ipv4Packet::new(packet_data) {
                        Some(p) => p,
                        None => { continue; }
                    };
                    
                    let icmp_data_from_outer_ip = outer_ipv4_packet.payload(); 

                    let icmp_packet_for_type_check = match IcmpPacket::new(icmp_data_from_outer_ip) {
                        Some(p) => p,
                        None => { continue; }
                    };

                    let mut matched_probe_opt: Option<SentProbe> = None;
                    
                    let original_datagram_bytes: &[u8];
                    if icmp_data_from_outer_ip.len() >= ICMP_ERROR_HEADER_LEN_BYTES {
                        original_datagram_bytes = &icmp_data_from_outer_ip[ICMP_ERROR_HEADER_LEN_BYTES..];
                    } else {
                        continue;
                    }

                    match icmp_packet_for_type_check.get_icmp_type() {
                        IcmpTypes::TimeExceeded | IcmpTypes::DestinationUnreachable => {
                            let icmp_type = icmp_packet_for_type_check.get_icmp_type(); 
                            if original_datagram_bytes.len() < IPV4_HEADER_MIN_LEN_BYTES {
                                continue;
                            }
                            
                            let inner_ip_packet = match Ipv4Packet::new(original_datagram_bytes) {
                                Some(p) => p,
                                None => {  
                                    continue; 
                                }
                            };
                            
                            let original_icmp_echo_bytes = inner_ip_packet.payload();
                            if original_icmp_echo_bytes.len() < 8 { 
                                continue; 
                            }

                            let original_type_val = original_icmp_echo_bytes[0];
                            let original_id = u16::from_be_bytes([original_icmp_echo_bytes[4], original_icmp_echo_bytes[5]]);
                            let original_seq = u16::from_be_bytes([original_icmp_echo_bytes[6], original_icmp_echo_bytes[7]]);

                            if original_type_val == IcmpTypes::EchoRequest.0 && original_id == icmp_identifier {
                                matched_probe_opt = active_probes_clone.lock().unwrap().remove(&original_seq);
                                if matched_probe_opt.is_some() && 
                                   icmp_type == IcmpTypes::DestinationUnreachable && 
                                   // VVV USING THE RENAMED VARIABLE VVV
                                   received_from_ip == IpAddr::V4(actual_target_ip_for_receiver) {
                                    *destination_reached_clone.lock().unwrap() = true;
                                }
                            }
                        }
                        IcmpTypes::EchoReply => {
                            if let Some(echo_reply_pkt) = echo_reply::EchoReplyPacket::new(icmp_packet_for_type_check.packet()){
                                if echo_reply_pkt.get_identifier() == icmp_identifier {
                                    matched_probe_opt = active_probes_clone.lock().unwrap().remove(&echo_reply_pkt.get_sequence_number());
                                    if matched_probe_opt.is_some() {
                                        *destination_reached_clone.lock().unwrap() = true;
                                    }
                                }
                            }
                        }
                        _ => { }
                    }

                    if let Some(probe_info) = matched_probe_opt {
                        let rtt = reception_time.duration_since(probe_info.sent_at);
                        let hop_info = HopInfo { 
                            ttl: probe_info.ttl, 
                            addr: Some(received_from_ip), 
                            rtt: Some(rtt) 
                        };
                        results_clone.lock().unwrap().insert(probe_info.ttl, hop_info);
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => {
                }
                Err(e) => {
                    eprintln!("[Receiver] Socket receive error: {}. Terminating receiver.", e); 
                    break;
                }
            }
            tokio::task::yield_now().await; 
        }
    });

    let send_socket = &*socket_arc;

    for ttl in args.start_ttl..=args.max_hops {
        if *destination_reached.lock().unwrap() {
            tokio::time::sleep(Duration::from_millis(args.hop_timeout_ms.min(200))).await; 
            if active_probes.lock().unwrap().is_empty() {
                 break; 
            }
        }

        let sequence_number = ttl as u16; 
        send_socket.set_ttl(ttl as u32)?;

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
        match send_socket.send_to(echo_req_packet.packet(), &target_saddr.into()) {
            Ok(_) => {
                active_probes.lock().unwrap().insert(
                    sequence_number, 
                    SentProbe { ttl, sent_at }
                );
            }
            Err(e) => {
                print_hop_info(&HopInfo { ttl, addr: Some(IpAddr::from([0,0,0,0])), rtt: Some(Duration::from_micros(0)) }); 
                eprintln!(" {:2}  Send error: {}", ttl, e);
                continue;
            }
        }

        let hop_start_time = Instant::now();
        let mut printed_for_ttl = false;
        loop {
            if let Some(hop_info) = results_map.lock().unwrap().get(&ttl) {
                print_hop_info(hop_info);
                printed_for_ttl = true;
                if hop_info.addr == Some(IpAddr::V4(target_ipv4)) {
                    *destination_reached.lock().unwrap() = true;
                }
                break;
            }

            if Instant::now().duration_since(hop_start_time) > Duration::from_millis(args.hop_timeout_ms) {
                if !results_map.lock().unwrap().contains_key(&ttl) { 
                    active_probes.lock().unwrap().remove(&sequence_number); 
                    print_hop_info(&HopInfo { ttl, addr: None, rtt: None });
                    printed_for_ttl = true;
                }
                break; 
            }
            if *destination_reached.lock().unwrap() && active_probes.lock().unwrap().is_empty() {
                break; 
            }
            tokio::time::sleep(Duration::from_millis(10)).await; 
        }
        
        if !printed_for_ttl {
             print_hop_info(&HopInfo { ttl, addr: None, rtt: None });
        }

        tokio::time::sleep(Duration::from_millis(args.send_interval_ms)).await;
    }
    
    let overall_receiver_timeout = Duration::from_millis(args.hop_timeout_ms.max(500)); 
    if tokio_timeout(overall_receiver_timeout, receiver_handle).await.is_err() {
    }

    Ok(())
}

/// Prints information for a single hop in a formatted way.
fn print_hop_info(hop_info: &HopInfo) {
    if let Some(addr) = hop_info.addr {
        if addr.is_unspecified() { 
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

/// Resolves a hostname or IP address string to an IPv4Addr.
async fn resolve_host(host: &str) -> Result<Ipv4Addr> {
    if let Ok(ipv4_addr) = host.parse::<Ipv4Addr>() {
        return Ok(ipv4_addr);
    }
    if let Ok(ip_addr) = host.parse::<IpAddr>() {
        if let IpAddr::V4(ipv4_addr) = ip_addr {
            return Ok(ipv4_addr);
        } else {
            bail!("IPv6 addresses ({}) are not supported by this version.", host);
        }
    }

    let addresses = tokio::net::lookup_host(format!("{}:0", host)).await
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
        assert_eq!(args.max_hops, 30); 
    }

    #[test]
    fn test_clap_args_parsing_custom() {
        let args = Args::try_parse_from(&[
            "mytraceroute",
            "--max-hops", "15",
            "--start-ttl", "2",
            "--hop-timeout-ms", "500",
            "--send-interval-ms", "100",
            "1.2.3.4"
        ]).unwrap();
        assert_eq!(args.host, "1.2.3.4");
        assert_eq!(args.max_hops, 15);
        assert_eq!(args.start_ttl, 2);
        assert_eq!(args.hop_timeout_ms, 500);
        assert_eq!(args.send_interval_ms, 100);
    }
}