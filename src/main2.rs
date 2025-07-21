//! Alternative main implementation using the new socket abstraction
//! This is a cleaner implementation that demonstrates how to use the new socket layer

use anyhow::{Context, Result};
use clap::Parser;
use ftr::socket::{ProbeInfo, ProbeProtocol, ResponseType};
use ftr::create_probe_socket;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Command-line arguments
#[derive(Parser, Debug)]
#[clap(author, version, about = "Fast parallel traceroute with ASN lookup")]
struct Args {
    /// Target host to trace
    host: String,
    
    /// Starting TTL value
    #[clap(short = 's', long, default_value_t = 1)]
    start_ttl: u8,
    
    /// Maximum number of hops
    #[clap(short = 'm', long, default_value_t = 30)]
    max_hops: u8,
    
    /// Probe timeout in milliseconds
    #[clap(long, default_value_t = 1000)]
    probe_timeout_ms: u64,
    
    /// Overall timeout in milliseconds
    #[clap(short = 'W', long, default_value_t = 3000)]
    overall_timeout_ms: u64,
    
    /// Use ICMP protocol (default)
    #[clap(short = 'I', long = "icmp")]
    use_icmp: bool,
    
    /// Use UDP protocol
    #[clap(short = 'U', long = "udp")]
    use_udp: bool,
    
    /// Verbose output
    #[clap(short = 'v', long)]
    verbose: bool,
}

#[derive(Debug, Clone)]
struct HopResult {
    ttl: u8,
    addr: Option<IpAddr>,
    rtt: Option<Duration>,
}

async fn resolve_host(host: &str) -> Result<Ipv4Addr> {
    use hickory_resolver::TokioResolver;
    use hickory_resolver::config::ResolverConfig;
    
    let resolver = TokioResolver::tokio(ResolverConfig::default(), Default::default());
    let response = resolver.ipv4_lookup(host).await
        .with_context(|| format!("Failed to resolve {}", host))?;
    
    response.iter()
        .next()
        .map(|ip| ip.0)
        .ok_or_else(|| anyhow::anyhow!("No IPv4 address found for {}", host))
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    
    // Resolve target
    let target = resolve_host(&args.host).await?;
    
    println!("traceroute to {} ({}), {} max hops",
        args.host, target, args.max_hops);
    
    // Determine protocol
    let protocol = if args.use_udp {
        Some(ProbeProtocol::Udp)
    } else {
        Some(ProbeProtocol::Icmp)
    };
    
    // Create socket with fallback
    let socket = create_probe_socket(IpAddr::V4(target), protocol)?;
    
    if args.verbose {
        println!("Using {} mode", socket.mode().description());
    }
    
    // Results storage
    let results = Arc::new(Mutex::new(HashMap::<u8, HopResult>::new()));
    let socket = Arc::new(socket);
    
    // Spawn receiver
    let recv_socket = Arc::clone(&socket);
    let recv_results = Arc::clone(&results);
    let recv_handle = tokio::spawn(async move {
        let start = Instant::now();
        let timeout = Duration::from_millis(args.overall_timeout_ms + 1000);
        
        while start.elapsed() < timeout {
            match recv_socket.recv_response(Duration::from_millis(100)) {
                Ok(Some(response)) => {
                    let hop = HopResult {
                        ttl: response.probe_info.ttl,
                        addr: Some(response.from_addr),
                        rtt: Some(response.rtt),
                    };
                    
                    recv_results.lock().unwrap()
                        .insert(response.probe_info.ttl, hop);
                    
                    // Check if we reached destination
                    if matches!(response.response_type, 
                        ResponseType::EchoReply | 
                        ResponseType::DestinationUnreachable(_)) {
                        break;
                    }
                }
                Ok(None) => continue,
                Err(e) => {
                    eprintln!("Receive error: {}", e);
                    break;
                }
            }
            
            if recv_socket.destination_reached() {
                break;
            }
        }
    });
    
    // Send probes
    for ttl in args.start_ttl..=args.max_hops {
        let socket = Arc::clone(&socket);
        let target_ip = IpAddr::V4(target);
        
        tokio::spawn(async move {
            if let Err(e) = socket.set_ttl(ttl) {
                eprintln!("Failed to set TTL {}: {}", ttl, e);
                return;
            }
            
            let probe = ProbeInfo {
                ttl,
                identifier: std::process::id() as u16,
                sequence: ttl as u16,
                sent_at: Instant::now(),
            };
            
            if let Err(e) = socket.send_probe(target_ip, probe) {
                eprintln!("Failed to send probe TTL {}: {}", ttl, e);
            }
        });
        
        // Small delay between probes
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    
    // Wait for results
    tokio::time::sleep(Duration::from_millis(args.overall_timeout_ms)).await;
    recv_handle.abort();
    
    // Print results
    let results = results.lock().unwrap();
    for ttl in args.start_ttl..=args.max_hops {
        if let Some(hop) = results.get(&ttl) {
            if let (Some(addr), Some(rtt)) = (hop.addr, hop.rtt) {
                println!("{:3}  {}  {:.3} ms", ttl, addr, rtt.as_secs_f64() * 1000.0);
            } else {
                println!("{:3}  * * *", ttl);
            }
            
            // Stop if we reached destination
            if socket.destination_reached() && hop.addr.is_some() {
                break;
            }
        } else {
            println!("{:3}  * * *", ttl);
        }
    }
    
    Ok(())
}