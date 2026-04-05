//! Tests for ASN lookup functionality

use super::*;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::sync::RwLock;

#[tokio::test]
async fn test_lookup_private_ip() {
    let cache = Arc::new(RwLock::new(crate::asn::cache::AsnCache::new()));
    let ip: Ipv4Addr = "192.168.1.1".parse().expect("valid IP");
    let result = lookup_asn_with_cache(ip, &cache).await;
    assert!(result.is_ok());
    let asn_info = result.expect("should succeed");
    assert_eq!(asn_info.asn, 0);
    assert_eq!(asn_info.name, "Private Network");
}

#[tokio::test]
async fn test_lookup_cgnat_ip() {
    let cache = Arc::new(RwLock::new(crate::asn::cache::AsnCache::new()));
    let ip: Ipv4Addr = "100.64.0.1".parse().expect("valid IP");
    let result = lookup_asn_with_cache(ip, &cache).await;
    let asn_info = result.expect("should succeed");
    assert_eq!(asn_info.asn, 0);
    assert_eq!(asn_info.name, "Carrier Grade NAT");
}

#[tokio::test]
async fn test_lookup_loopback() {
    let cache = Arc::new(RwLock::new(crate::asn::cache::AsnCache::new()));
    let ip: Ipv4Addr = "127.0.0.1".parse().expect("valid IP");
    let result = lookup_asn_with_cache(ip, &cache).await;
    let asn_info = result.expect("should succeed");
    assert_eq!(asn_info.asn, 0);
    assert_eq!(asn_info.name, "Loopback");
}

#[tokio::test]
async fn test_cache_usage() {
    let cache = Arc::new(RwLock::new(crate::asn::cache::AsnCache::new()));
    let ip: Ipv4Addr = "10.0.0.1".parse().expect("valid IP");

    let result1 = lookup_asn_with_cache(ip, &cache).await;
    assert!(result1.is_ok());

    let result2 = lookup_asn_with_cache(ip, &cache).await;
    assert!(result2.is_ok());
    assert_eq!(result1.expect("r1").name, result2.expect("r2").name);
}

#[tokio::test]
async fn test_special_ips() {
    let cache = Arc::new(RwLock::new(crate::asn::cache::AsnCache::new()));
    let test_cases = vec![
        ("0.0.0.0", "Special Use"),
        ("169.254.1.1", "Special Use"),
        ("255.255.255.255", "Special Use"),
        ("198.51.100.1", "Special Use"),
    ];

    for (ip_str, expected_name) in test_cases {
        let ip: Ipv4Addr = ip_str.parse().expect("valid IP");
        let result = lookup_asn_with_cache(ip, &cache).await;
        assert!(result.is_ok(), "Failed for IP: {ip_str}");
        let asn_info = result.expect("should succeed");
        assert_eq!(asn_info.asn, 0);
        assert_eq!(asn_info.name, expected_name, "Wrong name for IP: {ip_str}");
    }
}

#[tokio::test]
async fn test_lookup_public_ip() {
    // This test makes real DNS queries to Team Cymru. Under coverage
    // instrumentation (tarpaulin) it runs ~10x slower, so use a generous
    // timeout and skip gracefully on network issues.
    let result = tokio::time::timeout(std::time::Duration::from_secs(30), async {
        let cache = Arc::new(RwLock::new(crate::asn::cache::AsnCache::new()));
        let test_cases = vec![
            ("8.8.8.8", 15169u32, "GOOGLE"),
            ("1.1.1.1", 13335u32, "CLOUDFLARENET"),
        ];

        for (ip_str, expected_asn, expected_name_prefix) in test_cases {
            let ip: Ipv4Addr = ip_str.parse().expect("valid IP");
            let asn_info = lookup_asn_with_cache(ip, &cache)
                .await
                .unwrap_or_else(|e| panic!("ASN lookup failed for {ip_str}: {e:?}"));

            assert_eq!(asn_info.asn, expected_asn, "Wrong ASN for {ip_str}");
            assert!(
                asn_info.name.contains(expected_name_prefix),
                "ASN name for {ip_str} doesn't contain '{expected_name_prefix}': got '{}'",
                asn_info.name
            );
            assert!(!asn_info.prefix.is_empty());
            assert!(!asn_info.country_code.is_empty());
        }
    })
    .await;

    if result.is_err() {
        eprintln!("test_lookup_public_ip timed out (expected under coverage instrumentation)");
    }
}

#[tokio::test]
async fn test_concurrent_lookups() {
    use tokio::task::JoinSet;

    let ips = vec![
        Ipv4Addr::new(192, 168, 1, 1),
        Ipv4Addr::new(10, 0, 0, 1),
        Ipv4Addr::new(172, 16, 0, 1),
        Ipv4Addr::new(127, 0, 0, 1),
    ];

    let mut set = JoinSet::new();
    for ip in ips {
        let cache = Arc::new(RwLock::new(crate::asn::cache::AsnCache::new()));
        set.spawn(async move { lookup_asn_with_cache(ip, &cache).await });
    }

    let mut results = Vec::new();
    while let Some(result) = set.join_next().await {
        results.push(result.expect("task should not panic"));
    }

    assert_eq!(results.len(), 4);
    for result in results {
        assert!(result.is_ok());
    }
}

#[tokio::test]
async fn test_cache_multiple_ips_same_prefix() {
    let cache = Arc::new(RwLock::new(crate::asn::cache::AsnCache::new()));
    let ip1: Ipv4Addr = "192.168.1.1".parse().expect("valid IP");
    let ip2: Ipv4Addr = "192.168.1.2".parse().expect("valid IP");

    let result1 = lookup_asn_with_cache(ip1, &cache).await;
    assert!(result1.is_ok());

    let result2 = lookup_asn_with_cache(ip2, &cache).await;
    assert!(result2.is_ok());

    assert_eq!(result1.expect("r1").name, "Private Network");
    assert_eq!(result2.expect("r2").name, "Private Network");
}

#[test]
fn test_error_display() {
    let errors = vec![
        AsnLookupError::DnsError("timeout".to_string()),
        AsnLookupError::InvalidFormat,
        AsnLookupError::NotFound,
    ];

    for error in errors {
        let error_str = error.to_string();
        assert!(!error_str.is_empty());
    }
}
