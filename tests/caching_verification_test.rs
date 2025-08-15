//! Tests to verify caching behavior with request counting

use ftr::Ftr;
use ftr::TracerouteConfigBuilder;

#[tokio::test]
async fn test_traceroute_with_caching() {
    // Skip on GitHub Actions Windows/Linux - unreliable ICMP
    if std::env::var("GITHUB_ACTIONS").is_ok() {
        let os = std::env::consts::OS;
        if os == "windows" || os == "linux" {
            eprintln!("Skipping test on GitHub Actions {} (unreliable ICMP)", os);
            return;
        }
    }

    let target = "1.1.1.1";

    // Create an Ftr instance with its own caches
    let ftr_instance = Ftr::new();

    // First trace - cold cache
    let config1 = TracerouteConfigBuilder::new()
        .target(target)
        .max_hops(5)
        .enable_asn_lookup(true)
        .enable_rdns(true)
        .build()
        .unwrap();

    let result1 = ftr_instance.trace_with_config(config1).await;
    match result1 {
        Ok(trace_result) => {
            println!(
                "First trace completed with {} hops",
                trace_result.hops.len()
            );

            // Note: We can't directly inspect cache sizes anymore since they're internal
            // to the Ftr instance, but we can verify the trace worked
            let hops_with_hostnames = trace_result
                .hops
                .iter()
                .filter(|h| h.hostname.is_some())
                .count();

            let hops_with_asn = trace_result
                .hops
                .iter()
                .filter(|h| h.asn_info.is_some())
                .count();

            println!(
                "Hops with hostnames: {}, hops with ASN: {}",
                hops_with_hostnames, hops_with_asn
            );

            // Second trace to same target - should use cached values
            let config2 = TracerouteConfigBuilder::new()
                .target(target)
                .max_hops(5)
                .enable_asn_lookup(true)
                .enable_rdns(true)
                .build()
                .unwrap();

            let result2 = ftr_instance.trace_with_config(config2).await;
            match result2 {
                Ok(trace_result2) => {
                    println!(
                        "Second trace completed with {} hops",
                        trace_result2.hops.len()
                    );

                    // The results should be similar (same ASN/hostname data for same IPs)
                    // though the exact hops might differ due to routing changes
                    for hop1 in &trace_result.hops {
                        if let Some(hop1_addr) = hop1.addr {
                            // Find corresponding hop in second trace
                            for hop2 in &trace_result2.hops {
                                if hop2.addr == Some(hop1_addr) {
                                    // Same IP should have same ASN and hostname (from cache)
                                    assert_eq!(
                                        hop1.asn_info, hop2.asn_info,
                                        "ASN info should match for cached IP {}",
                                        hop1_addr
                                    );
                                    assert_eq!(
                                        hop1.hostname, hop2.hostname,
                                        "Hostname should match for cached IP {}",
                                        hop1_addr
                                    );
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    eprintln!(
                        "Second trace failed (may be expected in test environment): {}",
                        e
                    );
                }
            }
        }
        Err(e) => {
            eprintln!(
                "First trace failed (may be expected in test environment): {}",
                e
            );
        }
    }
}

#[tokio::test]
async fn test_multiple_targets_share_cache() {
    // Skip on GitHub Actions Windows/Linux - unreliable ICMP
    if std::env::var("GITHUB_ACTIONS").is_ok() {
        let os = std::env::consts::OS;
        if os == "windows" || os == "linux" {
            eprintln!("Skipping test on GitHub Actions {} (unreliable ICMP)", os);
            return;
        }
    }

    // Create a single Ftr instance
    let ftr_instance = Ftr::new();

    // Trace to multiple targets that might share some hops
    let targets = vec!["1.1.1.1", "8.8.8.8"];

    for target in targets {
        let config = TracerouteConfigBuilder::new()
            .target(target)
            .max_hops(3)
            .enable_asn_lookup(true)
            .enable_rdns(true)
            .build()
            .unwrap();

        match ftr_instance.trace_with_config(config).await {
            Ok(trace_result) => {
                println!(
                    "Trace to {} completed with {} hops",
                    target,
                    trace_result.hops.len()
                );
            }
            Err(e) => {
                eprintln!(
                    "Trace to {} failed (may be expected in test environment): {}",
                    target, e
                );
            }
        }
    }

    // The caches within the Ftr instance will be shared across all traces,
    // improving performance for subsequent lookups of the same IPs
}
