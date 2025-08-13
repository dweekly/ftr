//! Performance tests for the ftr library

use ftr::{trace_with_config, TracerouteConfig};
use std::time::{Duration, Instant};

#[tokio::test]
async fn test_traceroute_performance_localhost() {
    let start = Instant::now();

    let config = TracerouteConfig::builder()
        .target("127.0.0.1")
        .max_hops(5)
        .probe_timeout(Duration::from_millis(100))
        .overall_timeout(Duration::from_millis(500))
        .enable_asn_lookup(false)
        .enable_rdns(false)
        .build()
        .unwrap();

    let result = trace_with_config(config).await;
    let elapsed = start.elapsed();

    println!("Localhost traceroute took: {:?}", elapsed);
    assert!(result.is_ok(), "Traceroute failed: {:?}", result);
    assert!(
        elapsed < Duration::from_secs(1),
        "Traceroute took too long: {:?}",
        elapsed
    );
}

#[tokio::test]
async fn test_traceroute_performance_remote() {
    // Skip on GitHub Actions Windows/Linux - unreliable ICMP
    if std::env::var("GITHUB_ACTIONS").is_ok() {
        let os = std::env::consts::OS;
        if os == "windows" || os == "linux" {
            eprintln!("Skipping test on GitHub Actions {} (unreliable ICMP)", os);
            return;
        }
    }

    let start = Instant::now();

    let config = TracerouteConfig::builder()
        .target("8.8.8.8")
        .max_hops(10)
        .probe_timeout(Duration::from_millis(500))
        .overall_timeout(Duration::from_secs(3))
        .enable_asn_lookup(false)
        .enable_rdns(false)
        .build()
        .unwrap();

    let result = trace_with_config(config).await;
    let elapsed = start.elapsed();

    println!("Remote traceroute (no enrichment) took: {:?}", elapsed);
    assert!(result.is_ok(), "Traceroute failed: {:?}", result);

    // Count actual hops discovered
    if let Ok(trace_result) = result {
        let hops_with_responses = trace_result
            .hops
            .iter()
            .filter(|h| h.addr.is_some())
            .count();
        println!(
            "Discovered {} hops out of {}",
            hops_with_responses,
            trace_result.hops.len()
        );
    }
}

#[tokio::test]
async fn test_event_driven_efficiency() {
    // Skip on GitHub Actions Windows/Linux - unreliable ICMP
    if std::env::var("GITHUB_ACTIONS").is_ok() {
        let os = std::env::consts::OS;
        if os == "windows" || os == "linux" {
            eprintln!("Skipping test on GitHub Actions {} (unreliable ICMP)", os);
            return;
        }
    }

    // Test that demonstrates the efficiency of event-driven approach
    // by running multiple concurrent traceroutes
    let targets = vec!["1.1.1.1", "8.8.8.8", "9.9.9.9"];
    let start = Instant::now();

    let mut handles = vec![];

    for target in targets {
        let handle = tokio::spawn(async move {
            let config = TracerouteConfig::builder()
                .target(target)
                .max_hops(5)
                .probe_timeout(Duration::from_millis(500))
                .overall_timeout(Duration::from_secs(2))
                .enable_asn_lookup(false)
                .enable_rdns(false)
                .build()
                .unwrap();

            trace_with_config(config).await
        });
        handles.push(handle);
    }

    // Wait for all to complete
    let mut success_count = 0;
    for handle in handles {
        if let Ok(Ok(_)) = handle.await {
            success_count += 1;
        }
    }

    let elapsed = start.elapsed();
    println!("Concurrent traceroutes (3 targets) took: {:?}", elapsed);
    println!("Successful: {}/3", success_count);

    // With event-driven approach, concurrent traces should be efficient
    assert!(
        elapsed < Duration::from_secs(3),
        "Concurrent traces took too long"
    );
}
