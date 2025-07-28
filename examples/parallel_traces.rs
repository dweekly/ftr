//! Example of running multiple traces in parallel

use ftr::{trace_with_config, TracerouteConfigBuilder};
use std::time::{Duration, Instant};
use tokio::task::JoinSet;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Running parallel traces to multiple targets ===\n");

    let targets = vec![
        ("Google DNS", "8.8.8.8"),
        ("Cloudflare DNS", "1.1.1.1"),
        ("OpenDNS", "208.67.222.222"),
        ("Quad9 DNS", "9.9.9.9"),
    ];

    let start = Instant::now();
    let mut tasks = JoinSet::new();

    // Launch all traces in parallel
    for (name, target) in targets {
        tasks.spawn(async move {
            let config = TracerouteConfigBuilder::new()
                .target(target)
                .max_hops(20)
                .probe_timeout(Duration::from_millis(1000))
                .enable_asn_lookup(true)
                .enable_rdns(true)
                .build()
                .unwrap();

            let trace_start = Instant::now();
            let result = trace_with_config(config).await;
            let trace_duration = trace_start.elapsed();

            (name, target, result, trace_duration)
        });
    }

    // Collect results
    let mut results = Vec::new();
    while let Some(res) = tasks.join_next().await {
        match res {
            Ok(data) => results.push(data),
            Err(e) => eprintln!("Task failed: {}", e),
        }
    }

    let total_duration = start.elapsed();

    // Display results
    for (name, target, result, duration) in &results {
        println!("=== {} ({}) ===", name, target);
        match result {
            Ok(trace_result) => {
                println!("✓ Completed in {:.2}s", duration.as_secs_f64());
                println!("  Hops: {}", trace_result.hop_count());
                println!(
                    "  Destination reached: {}",
                    trace_result.destination_reached
                );

                if let Some(dest_hop) = trace_result.destination_hop() {
                    if let Some(hostname) = &dest_hop.hostname {
                        println!("  Destination hostname: {}", hostname);
                    }
                    if let Some(asn) = &dest_hop.asn_info {
                        println!("  Destination ASN: {} - {}", asn.asn, asn.name);
                    }
                }

                // Show path summary
                let asn_changes = count_asn_changes(trace_result);
                println!("  ASN changes along path: {}", asn_changes);
            }
            Err(e) => {
                println!("✗ Failed: {}", e);
            }
        }
        println!();
    }

    println!(
        "Total time for {} parallel traces: {:.2}s",
        results.len(),
        total_duration.as_secs_f64()
    );

    // Show cache statistics
    println!("\nCache statistics:");
    println!("  ASN cache entries: {}", ftr::asn::ASN_CACHE.len());
    println!("  rDNS cache entries: {}", ftr::dns::RDNS_CACHE.len());

    Ok(())
}

/// Count the number of ASN changes along the path
fn count_asn_changes(result: &ftr::TracerouteResult) -> usize {
    let mut changes = 0;
    let mut last_asn = None;

    for hop in &result.hops {
        if let Some(asn_info) = &hop.asn_info {
            if let Some(last) = &last_asn {
                if last != &asn_info.asn {
                    changes += 1;
                }
            }
            last_asn = Some(asn_info.asn.clone());
        }
    }

    changes
}
