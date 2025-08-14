//! Example demonstrating the performance benefits of caching in the ftr library
//!
//! This example shows how to:
//! 1. Provide a known public IP to avoid repeated detection
//! 2. Leverage ASN and rDNS caching for repeated traces
//! 3. Measure the performance improvement

use ftr::{trace_with_config, TracerouteConfigBuilder};
use std::time::Instant;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // First, detect our public IP once
    println!("Detecting public IP...");
    let public_ip_config = TracerouteConfigBuilder::new()
        .target("1.1.1.1")
        .max_hops(1)
        .enable_asn_lookup(true)
        .build()?;

    let initial_result = trace_with_config(public_ip_config).await?;
    let public_ip = initial_result.isp_info.map(|isp| isp.public_ip);

    if let Some(public_ip) = public_ip {
        println!("Detected public IP: {}", public_ip);
    } else {
        println!("Could not detect public IP, continuing without it");
    }

    // List of targets to trace
    let targets = vec![
        ("Google DNS", "8.8.8.8"),
        ("Cloudflare DNS", "1.1.1.1"),
        ("OpenDNS", "208.67.222.222"),
    ];

    println!("\n=== First run (cold cache) ===");
    let mut first_run_total = std::time::Duration::ZERO;

    for (name, target) in &targets {
        let start = Instant::now();

        let mut builder = TracerouteConfigBuilder::new()
            .target(*target)
            .max_hops(20)
            .enable_asn_lookup(true)
            .enable_rdns(true);

        // Use the detected public IP if available
        if let Some(ip) = public_ip {
            builder = builder.public_ip(ip);
        }

        let config = builder.build()?;
        let result = trace_with_config(config).await?;

        let duration = start.elapsed();
        first_run_total += duration;

        println!(
            "{}: {} hops in {:.2}s",
            name,
            result.hops.len(),
            duration.as_secs_f64()
        );
    }

    println!("\nFirst run total: {:.2}s", first_run_total.as_secs_f64());

    // Second run - should be faster due to caching
    println!("\n=== Second run (warm cache) ===");
    let mut second_run_total = std::time::Duration::ZERO;

    for (name, target) in &targets {
        let start = Instant::now();

        let mut builder = TracerouteConfigBuilder::new()
            .target(*target)
            .max_hops(20)
            .enable_asn_lookup(true)
            .enable_rdns(true);

        // Use the cached public IP
        if let Some(ip) = public_ip {
            builder = builder.public_ip(ip);
        }

        let config = builder.build()?;
        let result = trace_with_config(config).await?;

        let duration = start.elapsed();
        second_run_total += duration;

        println!(
            "{}: {} hops in {:.2}s",
            name,
            result.hops.len(),
            duration.as_secs_f64()
        );
    }

    println!("\nSecond run total: {:.2}s", second_run_total.as_secs_f64());

    // Calculate improvement
    let improvement = (first_run_total.as_secs_f64() - second_run_total.as_secs_f64())
        / first_run_total.as_secs_f64()
        * 100.0;

    println!(
        "\nPerformance improvement: {:.1}% faster with warm cache",
        improvement
    );

    // Note about caches
    println!("\nNote: Caches are now managed internally by the Ftr instance");
    println!("Each Ftr instance maintains its own ASN and rDNS caches for improved performance");

    Ok(())
}
