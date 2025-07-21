//! Test program to demonstrate multi-mode socket abstraction

use anyhow::Result;
use ftr::{create_probe_socket, create_probe_socket_with_mode, ProbeProtocol, SocketMode};
use ftr::socket::ProbeInfo;
use std::net::IpAddr;
use std::time::{Duration, Instant};

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command line args
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <host> [--udp] [--raw] [--dgram]", args[0]);
        eprintln!("  --udp    Use UDP protocol");
        eprintln!("  --raw    Force raw socket mode");
        eprintln!("  --dgram  Force datagram socket mode");
        std::process::exit(1);
    }
    
    let host = &args[1];
    let use_udp = args.contains(&"--udp".to_string());
    let force_raw = args.contains(&"--raw".to_string());
    let force_dgram = args.contains(&"--dgram".to_string());
    
    // Resolve hostname
    let target: IpAddr = tokio::net::lookup_host(format!("{}:0", host))
        .await?
        .next()
        .ok_or_else(|| anyhow::anyhow!("Failed to resolve host"))?
        .ip();
    
    println!("Testing traceroute to {} ({})", host, target);
    
    // Determine socket preferences
    let preferred_protocol = if use_udp {
        Some(ProbeProtocol::Udp)
    } else {
        None // Will try ICMP first, then fall back
    };
    
    let preferred_mode = if force_raw {
        Some(SocketMode::Raw)
    } else if force_dgram {
        Some(SocketMode::Dgram)
    } else {
        None
    };
    
    // Create socket with preferences
    let probe_socket = match preferred_mode {
        Some(mode) => create_probe_socket_with_mode(target, preferred_protocol, Some(mode))?,
        None => create_probe_socket(target, preferred_protocol)?,
    };
    println!("Using {} mode", probe_socket.mode().description());
    
    // Send a few probes
    let mut sequence = 1u16;
    let identifier = std::process::id() as u16;
    
    for ttl in 1..=3 {
        // Set TTL
        probe_socket.set_ttl(ttl)?;
        
        // Create probe info
        let probe_info = ProbeInfo {
            ttl,
            identifier,
            sequence,
            sent_at: Instant::now(),
        };
        
        // Send probe
        println!("Sending probe with TTL={}", ttl);
        probe_socket.send_probe(target, probe_info)?;
        
        // Try to receive response
        match probe_socket.recv_response(Duration::from_secs(1))? {
            Some(response) => {
                println!(
                    "  {} from {} in {:.3}ms - {:?}",
                    ttl,
                    response.from_addr,
                    response.rtt.as_secs_f64() * 1000.0,
                    response.response_type
                );
            }
            None => {
                println!("  {} * (timeout)", ttl);
            }
        }
        
        sequence += 1;
        
        // Check if destination reached
        if probe_socket.destination_reached() {
            println!("Destination reached!");
            break;
        }
    }
    
    Ok(())
}