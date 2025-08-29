//! Integration test for the new service-oriented API

use ftr::Ftr;
use std::net::IpAddr;

#[tokio::test]
async fn test_ftr_convenience_methods() {
    let ftr = Ftr::new();

    // Test ASN lookup with a public IP
    let ip: IpAddr = "8.8.8.8".parse().unwrap();
    let result = ftr.lookup_asn(ip).await;

    // Only skip in CI environments where network may be unreliable
    if std::env::var("CI").is_ok() && result.is_err() {
        eprintln!(
            "Skipping test in CI due to network error: {:?}",
            result.err()
        );
        return;
    }

    assert!(result.is_ok(), "ASN lookup failed: {:?}", result.err());
    let asn_info = result.unwrap();
    assert_eq!(asn_info.asn, 15169);
    // ASN name might vary between DNS services - just check it's not empty
    assert!(!asn_info.name.is_empty(), "ASN name should not be empty");

    // Test reverse DNS lookup
    let dns_ip: IpAddr = "8.8.8.8".parse().unwrap();
    let result = ftr.lookup_rdns(dns_ip).await;
    if let Ok(hostname) = result {
        assert!(hostname.contains("dns.google") || hostname.contains("google"));
    }
    // It's okay if reverse DNS fails in test environment
}

#[tokio::test]
async fn test_service_isolation() {
    // Create two Ftr instances
    let ftr1 = Ftr::new();
    let ftr2 = Ftr::new();

    // Perform lookups on both
    let ip: IpAddr = "1.1.1.1".parse().unwrap();

    let result1 = ftr1.lookup_asn(ip).await;
    let result2 = ftr2.lookup_asn(ip).await;

    // Only skip in CI environments where network may be unreliable
    if std::env::var("CI").is_ok() && (result1.is_err() || result2.is_err()) {
        eprintln!("Skipping test in CI due to network error");
        return;
    }

    // Both should succeed independently
    assert!(result1.is_ok(), "First lookup failed: {:?}", result1.err());
    assert!(result2.is_ok(), "Second lookup failed: {:?}", result2.err());

    // Results should be the same (same IP = same ASN)
    assert_eq!(result1.unwrap().asn, result2.unwrap().asn);
}

#[tokio::test]
async fn test_cache_clearing() {
    let ftr = Ftr::new();

    // Perform a lookup to populate caches
    let ip: IpAddr = "8.8.4.4".parse().unwrap();
    let first_result = ftr.lookup_asn(ip).await;

    // Only skip in CI environments where network may be unreliable
    if std::env::var("CI").is_ok() && first_result.is_err() {
        eprintln!("Skipping cache test in CI due to network error");
        return;
    }

    // Clear all caches
    ftr.clear_all_caches().await;

    // Should still work after clearing
    let result = ftr.lookup_asn(ip).await;

    // Only skip in CI environments where network may be unreliable
    if std::env::var("CI").is_ok() && result.is_err() {
        eprintln!("Skipping cache test in CI due to network error after clear");
        return;
    }

    assert!(
        result.is_ok(),
        "Lookup after cache clear failed: {:?}",
        result.err()
    );
}

#[tokio::test]
async fn test_direct_service_access() {
    let ftr = Ftr::new();

    // Access ASN service directly (no locking needed)
    let asn_service = &ftr.services.asn;

    let ip: IpAddr = "1.1.1.1".parse().unwrap();
    let result = asn_service.lookup(ip).await;

    // Only skip in CI environments where network may be unreliable
    if std::env::var("CI").is_ok() && result.is_err() {
        eprintln!(
            "Skipping test in CI due to network error: {:?}",
            result.err()
        );
        return;
    }

    assert!(result.is_ok(), "ASN lookup failed: {:?}", result.err());

    // Check cache stats
    let stats = asn_service.cache_stats().await;
    assert!(!stats.is_empty); // Should have at least one entry after lookup
}

#[tokio::test]
async fn test_private_ip_handling() {
    let ftr = Ftr::new();

    // Test with private IP
    let private_ip: IpAddr = "192.168.1.1".parse().unwrap();
    let result = ftr.lookup_asn(private_ip).await;

    assert!(result.is_ok());
    let asn_info = result.unwrap();
    assert_eq!(asn_info.asn, 0); // Private IPs have ASN 0
    assert_eq!(asn_info.name, "Private Network");
}
