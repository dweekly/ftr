//! Tests for the new handle pattern API
//!
//! These tests verify that the new Ftr struct works correctly
//! and can coexist with the legacy global cache API during migration.

use ftr::{Ftr, TracerouteConfigBuilder};

#[tokio::test]
async fn test_ftr_instance_basic_trace() {
    // Skip on GitHub Actions where ICMP might not work
    if std::env::var("GITHUB_ACTIONS").is_ok() {
        let os = std::env::consts::OS;
        if os == "windows" || os == "linux" {
            eprintln!("Skipping test on GitHub Actions {} runner", os);
            return;
        }
    }

    let ftr = Ftr::new();
    let result = ftr.trace("127.0.0.1").await;

    assert!(result.is_ok(), "Failed to trace localhost: {:?}", result);
    let trace_result = result.unwrap();
    assert!(
        !trace_result.hops.is_empty(),
        "Should have at least one hop"
    );
}

#[tokio::test]
async fn test_ftr_instance_with_config() {
    // Skip on GitHub Actions where ICMP might not work
    if std::env::var("GITHUB_ACTIONS").is_ok() {
        let os = std::env::consts::OS;
        if os == "windows" || os == "linux" {
            eprintln!("Skipping test on GitHub Actions {} runner", os);
            return;
        }
    }

    let ftr = Ftr::new();
    let config = TracerouteConfigBuilder::new()
        .target("127.0.0.1")
        .max_hops(5)
        .queries(1)
        .build()
        .expect("Failed to build config");

    let result = ftr.trace_with_config(config).await;

    assert!(result.is_ok(), "Failed to trace with config: {:?}", result);
    let trace_result = result.unwrap();
    assert!(
        !trace_result.hops.is_empty(),
        "Should have at least one hop"
    );
}

#[tokio::test]
async fn test_multiple_ftr_instances() {
    // This test verifies that multiple Ftr instances can coexist
    // In the future, this will test cache isolation
    let ftr1 = Ftr::new();
    let ftr2 = Ftr::new();

    // For now, both instances use the global caches
    // After Phase 2, they will have isolated caches
    assert!(ftr1.trace("127.0.0.1").await.is_ok());
    assert!(ftr2.trace("127.0.0.1").await.is_ok());
}

#[tokio::test]
async fn test_ftr_with_custom_caches() {
    // Test creating an Ftr instance with pre-initialized caches
    let asn_cache = ftr::asn::cache::AsnCache::new();
    let rdns_cache = ftr::dns::cache::RdnsCache::with_default_ttl();
    let stun_cache = ftr::public_ip::stun_cache::StunCache::new();

    let ftr = Ftr::with_caches(Some(asn_cache), Some(rdns_cache), Some(stun_cache));

    // Verify it works
    let result = ftr.trace("127.0.0.1").await;
    assert!(result.is_ok(), "Failed with custom caches: {:?}", result);
}

#[tokio::test]
async fn test_ftr_default_impl() {
    let ftr = Ftr::default();
    assert!(ftr.trace("127.0.0.1").await.is_ok());
}

#[tokio::test]
async fn test_legacy_api_still_works() {
    // Verify the old API continues to function
    let result = ftr::trace("127.0.0.1").await;
    assert!(result.is_ok(), "Legacy API should still work: {:?}", result);
}
