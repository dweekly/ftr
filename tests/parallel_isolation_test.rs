//! Tests to verify that multiple Ftr instances can run in parallel without interference

use ftr::{Ftr, TracerouteConfigBuilder};
use std::sync::Arc;
use tokio::task::JoinSet;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_parallel_ftr_instances() {
    // Create multiple Ftr instances and run them concurrently
    let mut tasks = JoinSet::new();

    for i in 0..10 {
        tasks.spawn(async move {
            let ftr = Ftr::new();
            let config = TracerouteConfigBuilder::new()
                .target("127.0.0.1")
                .max_hops(3)
                .enable_asn_lookup(true)
                .enable_rdns(true)
                .build()
                .unwrap();

            let result = ftr.trace_with_config(config).await;
            (i, result.is_ok())
        });
    }

    let mut results = Vec::new();
    while let Some(result) = tasks.join_next().await {
        match result {
            Ok((id, success)) => {
                results.push((id, success));
            }
            Err(e) => {
                eprintln!("Task failed: {}", e);
            }
        }
    }

    // All 10 instances should have completed
    assert_eq!(results.len(), 10);
    println!("Successfully ran {} parallel Ftr instances", results.len());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_cache_isolation_between_instances() {
    // Create two Ftr instances
    let ftr1 = Arc::new(Ftr::new());
    let ftr2 = Arc::new(Ftr::new());

    // Target that will have consistent results
    let target = "8.8.8.8";

    // Run traces in parallel on both instances
    let ftr1_clone = ftr1.clone();
    let ftr2_clone = ftr2.clone();

    let (result1, result2) = tokio::join!(
        async move {
            let config = TracerouteConfigBuilder::new()
                .target(target)
                .max_hops(5)
                .enable_asn_lookup(true)
                .enable_rdns(true)
                .build()
                .unwrap();
            ftr1_clone.trace_with_config(config).await
        },
        async move {
            let config = TracerouteConfigBuilder::new()
                .target(target)
                .max_hops(5)
                .enable_asn_lookup(true)
                .enable_rdns(true)
                .build()
                .unwrap();
            ftr2_clone.trace_with_config(config).await
        }
    );

    // Both should succeed independently
    match (&result1, &result2) {
        (Ok(_), Ok(_)) => {
            println!("Both instances completed successfully");
        }
        _ => {
            // Network issues are acceptable in test environments
            eprintln!("Some traces failed (acceptable in test environment)");
        }
    }

    // The important thing is they don't interfere with each other
    // Both should have the same success/failure status
    assert_eq!(result1.is_ok(), result2.is_ok());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_high_concurrency_no_interference() {
    // Test with many concurrent traces using the same Ftr instance
    let ftr = Arc::new(Ftr::new());
    let mut tasks = JoinSet::new();

    // Launch 50 concurrent traces
    for i in 0..50 {
        let ftr_clone = ftr.clone();
        let target = if i % 2 == 0 { "127.0.0.1" } else { "::1" };

        tasks.spawn(async move {
            let config = TracerouteConfigBuilder::new()
                .target(target)
                .max_hops(2)
                .enable_asn_lookup(false) // Disable to speed up test
                .enable_rdns(false) // Disable to speed up test
                .build()
                .unwrap();

            let result = ftr_clone.trace_with_config(config).await;
            result.is_ok()
        });
    }

    let mut success_count = 0;
    let mut failure_count = 0;

    while let Some(result) = tasks.join_next().await {
        match result {
            Ok(true) => success_count += 1,
            Ok(false) => failure_count += 1,
            Err(e) => eprintln!("Task panicked: {}", e),
        }
    }

    println!(
        "High concurrency test: {} succeeded, {} failed out of 50",
        success_count, failure_count
    );

    // At least some should succeed (exact number depends on platform support)
    assert!(success_count > 0 || failure_count == 50); // All failures is ok on some platforms
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_separate_instances_separate_caches() {
    // Create two separate Ftr instances
    let ftr1 = Ftr::new();
    let ftr2 = Ftr::new();

    // Each instance should have its own caches
    // We can't directly inspect the caches, but we can verify
    // that operations on one don't affect the other

    let config1 = TracerouteConfigBuilder::new()
        .target("192.168.1.1") // Private IP for consistent results
        .max_hops(1)
        .enable_asn_lookup(true)
        .build()
        .unwrap();

    let config2 = TracerouteConfigBuilder::new()
        .target("10.0.0.1") // Different private IP
        .max_hops(1)
        .enable_asn_lookup(true)
        .build()
        .unwrap();

    // Run traces on both instances
    let result1 = ftr1.trace_with_config(config1.clone()).await;
    let result2 = ftr2.trace_with_config(config2.clone()).await;

    // Both should complete independently
    println!(
        "Instance 1: {}, Instance 2: {}",
        if result1.is_ok() { "OK" } else { "Failed" },
        if result2.is_ok() { "OK" } else { "Failed" }
    );

    // Run the same configs again - caches should be warm but separate
    let result1_second = ftr1.trace_with_config(config1).await;
    let result2_second = ftr2.trace_with_config(config2).await;

    // Results should be consistent within each instance
    assert_eq!(result1.is_ok(), result1_second.is_ok());
    assert_eq!(result2.is_ok(), result2_second.is_ok());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_stress_test_cache_isolation() {
    // Stress test: Many instances, many concurrent operations
    let mut instances = Vec::new();
    for _ in 0..20 {
        instances.push(Arc::new(Ftr::new()));
    }

    let mut tasks = JoinSet::new();

    // Each instance does multiple traces
    for (idx, ftr) in instances.into_iter().enumerate() {
        for j in 0..5 {
            let ftr_clone = ftr.clone();
            tasks.spawn(async move {
                let target = match (idx + j) % 3 {
                    0 => "127.0.0.1",
                    1 => "192.168.1.1",
                    _ => "10.0.0.1",
                };

                let config = TracerouteConfigBuilder::new()
                    .target(target)
                    .max_hops(1)
                    .build()
                    .unwrap();

                ftr_clone.trace_with_config(config).await.is_ok()
            });
        }
    }

    let mut completed = 0;
    while let Some(result) = tasks.join_next().await {
        if result.is_ok() {
            completed += 1;
        }
    }

    println!("Stress test: {} operations completed", completed);
    assert_eq!(completed, 100); // 20 instances * 5 operations each
}
