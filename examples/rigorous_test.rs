//! Rigorous test of Windows ICMP implementation using ftr as a library

use ftr::traceroute::async_api::trace_with_config_async;
use ftr::TracerouteConfig;
use std::net::IpAddr;
use std::time::{Duration, Instant};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("FTR Windows ICMP Rigorous Test (Library Mode)");
    println!("============================================\n");

    // Test configurations
    let test_configs = vec![
        ("70ms + enrichment (critical)", "8.8.8.8", 70, true, true),
        ("70ms no enrichment", "8.8.8.8", 70, false, false),
        ("100ms + enrichment", "8.8.8.8", 100, true, true),
        ("30ms + enrichment", "8.8.8.8", 30, true, true),
        ("50ms + enrichment", "8.8.8.8", 50, true, true),
    ];

    for (name, target, timeout_ms, enable_asn, enable_rdns) in test_configs {
        println!("\n=== Testing: {} ===", name);

        let target_ip: IpAddr = target.parse()?;
        let iterations = 30;
        let mut successes = 0;
        let mut total_hops = Vec::new();
        let mut hop_11_15_counts = Vec::new();
        let mut execution_times = Vec::new();
        let mut errors = 0;

        for i in 1..=iterations {
            print!("Run {}/{}: ", i, iterations);

            let config = TracerouteConfig::builder()
                .target(target_ip.to_string())
                .probe_timeout(Duration::from_millis(timeout_ms))
                .max_hops(30)
                .enable_asn_lookup(enable_asn)
                .enable_rdns(enable_rdns)
                .build()?;

            let start = Instant::now();
            match trace_with_config_async(config).await {
                Ok(result) => {
                    let elapsed = start.elapsed();
                    execution_times.push(elapsed.as_millis());

                    // Count total hops
                    let hop_count = result.hops.len();
                    total_hops.push(hop_count);

                    // Count hops in range 11-15
                    let hops_11_15 = result
                        .hops
                        .iter()
                        .filter(|h| h.ttl >= 11 && h.ttl <= 15)
                        .count();
                    hop_11_15_counts.push(hops_11_15);

                    if hops_11_15 == 5 {
                        successes += 1;
                        println!("OK ({}ms)", elapsed.as_millis());
                    } else {
                        println!(
                            "FAIL - Only {}/5 hops in range 11-15 ({}ms)",
                            hops_11_15,
                            elapsed.as_millis()
                        );

                        // Debug: show which hops were detected
                        if hops_11_15 < 5 {
                            for ttl in 11..=15 {
                                if !result.hops.iter().any(|h| h.ttl == ttl) {
                                    println!("  Missing hop {}", ttl);
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    errors += 1;
                    println!("ERROR: {}", e);
                }
            }

            // Brief pause between runs
            tokio::time::sleep(Duration::from_millis(200)).await;
        }

        // Calculate statistics
        let success_rate = (successes as f64 / iterations as f64) * 100.0;
        let avg_hops = total_hops.iter().sum::<usize>() as f64 / total_hops.len() as f64;
        let avg_time = execution_times.iter().sum::<u128>() as f64 / execution_times.len() as f64;

        println!("\nResults for {}:", name);
        println!(
            "  Success rate: {:.1}% ({}/{})",
            success_rate, successes, iterations
        );
        println!("  Average hops detected: {:.1}", avg_hops);
        println!("  Average execution time: {:.0}ms", avg_time);
        println!("  Errors: {}", errors);

        if name.contains("critical") {
            if success_rate >= 80.0 {
                println!("  ✓ PASS - Critical test meets 80% threshold");
            } else {
                println!("  ✗ FAIL - Critical test below 80% threshold");
            }
        }
    }

    // Stress test - rapid succession
    println!("\n=== Stress Test ===");
    println!("Running 10 traces in rapid succession...");

    let mut stress_times = Vec::new();
    for i in 1..=10 {
        let config = TracerouteConfig::builder()
            .target("1.1.1.1")
            .probe_timeout(Duration::from_millis(70))
            .max_hops(15)
            .build()?;

        let start = Instant::now();
        let _ = trace_with_config_async(config).await;
        let elapsed = start.elapsed();
        stress_times.push(elapsed.as_millis());
        println!("  Run {}: {}ms", i, elapsed.as_millis());
    }

    let avg_stress = stress_times.iter().sum::<u128>() as f64 / stress_times.len() as f64;
    let max_stress = *stress_times.iter().max().unwrap() as f64;
    println!("  Average: {:.0}ms, Max: {:.0}ms", avg_stress, max_stress);

    if max_stress < avg_stress * 2.0 {
        println!("  ✓ Performance remains consistent under stress");
    } else {
        println!("  ✗ Performance degrades under stress");
    }

    // Test warning functionality
    println!("\n=== Warning Test ===");
    #[cfg(target_os = "windows")]
    {
        println!("On Windows, short timeouts with enrichment should trigger a warning.");
        println!("Check the console output above for warning messages.");
    }

    println!("\n=== Test Complete ===");
    Ok(())
}
