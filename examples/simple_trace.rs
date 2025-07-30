//! Simple example of using ftr as a library

use ftr::{trace, TracerouteConfigBuilder};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Example 1: Simple trace with defaults
    println!("=== Simple trace to 1.1.1.1 ===");
    match trace("1.1.1.1").await {
        Ok(result) => {
            println!(
                "Trace to {} completed in {:?}",
                result.target, result.total_duration
            );
            println!("Found {} hops", result.hop_count());

            for hop in &result.hops {
                if let Some(addr) = hop.addr {
                    print!("{:2}. {} ", hop.ttl, addr);

                    if let Some(hostname) = &hop.hostname {
                        print!("({}) ", hostname);
                    }

                    if let Some(rtt) = hop.rtt_ms() {
                        print!("{:.2}ms ", rtt);
                    }

                    if let Some(asn) = &hop.asn_info {
                        print!("[{} - {}] ", asn.asn, asn.name);
                    }

                    println!();
                } else {
                    println!("{:2}. * * *", hop.ttl);
                }
            }

            if let Some(isp) = &result.isp_info {
                println!("\nYour ISP: {} ({})", isp.name, isp.asn);
            }
        }
        Err(e) => {
            eprintln!("Trace failed: {}", e);
            eprintln!("You may need to run with elevated privileges (sudo)");
        }
    }

    println!("\n=== Custom configuration example ===");

    // Example 2: Custom configuration
    let config = TracerouteConfigBuilder::new()
        .target("cloudflare.com")
        .max_hops(20)
        .probe_timeout(Duration::from_millis(500))
        .queries_per_hop(1)
        .enable_asn_lookup(true)
        .enable_rdns(true)
        .verbose(1)
        .build()?;

    match ftr::trace_with_config(config).await {
        Ok(result) => {
            println!("Trace completed!");
            println!("Protocol used: {:?}", result.protocol_used);
            println!("Socket mode: {:?}", result.socket_mode_used);
            println!("Destination reached: {}", result.destination_reached);

            // Show statistics
            if let Some(avg_rtt) = result.average_rtt_ms() {
                println!("Average RTT: {:.2}ms", avg_rtt);
            }

            // Count hops by segment
            let lan_count = result.hops_in_segment(ftr::SegmentType::Lan).len();
            let isp_count = result.hops_in_segment(ftr::SegmentType::Isp).len();
            let beyond_count = result.hops_in_segment(ftr::SegmentType::Beyond).len();

            println!(
                "Hops by segment: {} LAN, {} ISP, {} BEYOND",
                lan_count, isp_count, beyond_count
            );
        }
        Err(e) => {
            eprintln!("Custom trace failed: {}", e);
        }
    }

    Ok(())
}
