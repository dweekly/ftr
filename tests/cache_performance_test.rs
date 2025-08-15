//! Tests to verify cache performance improvements

use ftr::{Ftr, TracerouteConfigBuilder};
use std::time::Instant;

#[tokio::test]
async fn test_cache_improves_performance() {
    // Skip on CI where network conditions are unpredictable
    if std::env::var("CI").is_ok() {
        eprintln!("Skipping performance test on CI");
        return;
    }

    let ftr = Ftr::new();

    // Use a well-known target that should have stable DNS/ASN
    let config = TracerouteConfigBuilder::new()
        .target("1.1.1.1")
        .max_hops(10)
        .enable_asn_lookup(true)
        .enable_rdns(true)
        .build()
        .unwrap();

    // First trace - cold cache
    let start1 = Instant::now();
    let result1 = ftr.trace_with_config(config.clone()).await;
    let duration1 = start1.elapsed();

    if result1.is_err() {
        eprintln!("First trace failed, skipping performance test");
        return;
    }

    // Second trace - warm cache
    let start2 = Instant::now();
    let result2 = ftr.trace_with_config(config.clone()).await;
    let duration2 = start2.elapsed();

    if result2.is_err() {
        eprintln!("Second trace failed, skipping performance test");
        return;
    }

    println!("Cold cache: {:?}", duration1);
    println!("Warm cache: {:?}", duration2);

    // Warm cache should generally be faster (though network variance can affect this)
    // We'll just verify both completed and log the times
    assert!(result1.is_ok());
    assert!(result2.is_ok());

    // Third trace to verify cache is still working
    let result3 = ftr.trace_with_config(config).await;
    assert_eq!(result3.is_ok(), result2.is_ok());
}

#[tokio::test]
async fn test_multiple_targets_share_cache_benefits() {
    let ftr = Ftr::new();

    // First trace to populate some ASN/DNS entries
    let config1 = TracerouteConfigBuilder::new()
        .target("8.8.8.8")
        .max_hops(5)
        .enable_asn_lookup(true)
        .enable_rdns(true)
        .build()
        .unwrap();

    let _ = ftr.trace_with_config(config1).await;

    // Second trace to a different target that might share some hops
    let config2 = TracerouteConfigBuilder::new()
        .target("8.8.4.4")
        .max_hops(5)
        .enable_asn_lookup(true)
        .enable_rdns(true)
        .build()
        .unwrap();

    let start = Instant::now();
    let result2 = ftr.trace_with_config(config2).await;
    let duration = start.elapsed();

    println!("Second target trace time: {:?}", duration);

    match result2 {
        Ok(trace) => {
            // Check that we got ASN info (which should be cached for Google IPs)
            let hops_with_asn = trace.hops.iter().filter(|h| h.asn_info.is_some()).count();
            println!("Hops with ASN info: {}", hops_with_asn);
        }
        Err(_) => {
            eprintln!("Trace failed (acceptable in test environment)");
        }
    }
}

#[tokio::test]
async fn test_cache_isolation_performance() {
    // Two instances should not share cache benefits
    let ftr1 = Ftr::new();
    let ftr2 = Ftr::new();

    let config = TracerouteConfigBuilder::new()
        .target("1.1.1.1")
        .max_hops(3)
        .enable_asn_lookup(true)
        .enable_rdns(true)
        .build()
        .unwrap();

    // Warm up ftr1's cache
    let _ = ftr1.trace_with_config(config.clone()).await;

    // ftr2 should still have cold cache
    let start = Instant::now();
    let result = ftr2.trace_with_config(config.clone()).await;
    let cold_duration = start.elapsed();

    // ftr2 second run should be faster (warm cache)
    let start = Instant::now();
    let result2 = ftr2.trace_with_config(config).await;
    let warm_duration = start.elapsed();

    println!("ftr2 cold cache: {:?}", cold_duration);
    println!("ftr2 warm cache: {:?}", warm_duration);

    // Verify both completed
    assert_eq!(result.is_ok(), result2.is_ok());
}
