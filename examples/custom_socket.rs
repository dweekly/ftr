//! Example of using ftr with custom socket configuration

use ftr::{trace_with_config, ProbeProtocol, SocketMode, TracerouteConfigBuilder};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Testing different socket modes ===\n");

    let target = "1.1.1.1";

    // Test different protocol/mode combinations
    let configurations = vec![
        ("ICMP Raw", ProbeProtocol::Icmp, SocketMode::Raw),
        ("ICMP Datagram", ProbeProtocol::Icmp, SocketMode::Dgram),
        ("UDP Datagram", ProbeProtocol::Udp, SocketMode::Dgram),
    ];

    for (name, protocol, mode) in configurations {
        println!("Testing {} mode...", name);

        let config = TracerouteConfigBuilder::new()
            .target(target)
            .protocol(protocol)
            .socket_mode(mode)
            .max_hops(10)
            .probe_timeout(Duration::from_millis(500))
            .verbose(true)
            .build()?;

        match trace_with_config(config).await {
            Ok(result) => {
                println!("✓ {} mode succeeded", name);
                println!(
                    "  Protocol: {:?}, Mode: {:?}",
                    result.protocol_used, result.socket_mode_used
                );
                println!(
                    "  Found {} hops in {:?}",
                    result.hop_count(),
                    result.total_duration
                );

                // Show first few hops
                for hop in result.hops.iter().take(3) {
                    if let Some(addr) = hop.addr {
                        println!("  {}. {} ({:?}ms)", hop.ttl, addr, hop.rtt_ms());
                    }
                }
                println!();
            }
            Err(e) => {
                println!("✗ {} mode failed: {}", name, e);
                println!("  This mode may require elevated privileges");
                println!();
            }
        }
    }

    // Example: UDP trace with custom port
    println!("=== UDP trace with custom port ===");
    let config = TracerouteConfigBuilder::new()
        .target("example.com")
        .protocol(ProbeProtocol::Udp)
        .port(33434) // Traditional traceroute UDP port
        .max_hops(15)
        .build()?;

    match trace_with_config(config).await {
        Ok(result) => {
            println!("UDP trace completed using port 33434");
            println!("Hops: {}", result.hop_count());
        }
        Err(e) => {
            println!("UDP trace failed: {}", e);
        }
    }

    Ok(())
}
