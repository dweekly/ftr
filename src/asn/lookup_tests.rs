//! Tests for ASN lookup functionality

use super::*;
use std::net::{Ipv4Addr, Ipv6Addr};
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
            let result = lookup_asn_with_cache(ip, &cache).await;
            assert!(result.is_ok(), "ASN lookup failed for {ip_str}: {result:?}");
            let asn_info = result.expect("ASN lookup should succeed");

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
fn test_origin6_query_name_full_expansion() {
    // The full 32-nibble expansion of 2001:4860:4860::8888, least
    // significant nibble first — exact string validated against the live
    // Cymru zone by examples/spike_asn6.rs.
    let addr: Ipv6Addr = "2001:4860:4860::8888".parse().expect("valid IP");
    assert_eq!(
        origin6_query_name(&addr),
        "8.8.8.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.6.8.4.0.6.8.4.1.0.0.2.origin6.asn.cymru.com"
    );
}

#[test]
fn test_origin6_query_name_loopback() {
    let addr: Ipv6Addr = "::1".parse().expect("valid IP");
    assert_eq!(
        origin6_query_name(&addr),
        "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.origin6.asn.cymru.com"
    );
}

#[test]
fn test_parse_cymru_origin_txt() {
    // Payload observed live from the origin6 zone (docs/IPV6_DESIGN.md)
    let origin = parse_cymru_origin_txt("15169 | 2001:4860::/32 | US | arin | 2005-03-14")
        .expect("valid payload");
    assert_eq!(origin.asn, 15169);
    assert_eq!(origin.prefix, "2001:4860::/32");
    assert_eq!(origin.country_code, "US");
    assert_eq!(origin.registry, "arin");

    // Multi-origin prefixes list several ASNs; the first is used
    let origin = parse_cymru_origin_txt("15169 36040 | 8.8.8.0/24 | US | arin | 2023-12-28")
        .expect("valid payload");
    assert_eq!(origin.asn, 15169);

    // Too few fields is a format error
    assert!(matches!(
        parse_cymru_origin_txt("15169 | 2001:4860::/32"),
        Err(AsnLookupError::InvalidFormat)
    ));
}

#[test]
fn test_special_ipv6_classification() {
    let cases: &[(&str, Option<&str>)] = &[
        ("::1", Some("Loopback")),
        ("::", Some("Special Use")),
        // fe80::/10 link-local, including the top of the range (febf::)
        ("fe80::1", Some("Special Use")),
        ("febf:ffff::1", Some("Special Use")),
        // fc00::/7 unique local (both halves)
        ("fc00::1", Some("Private Network")),
        ("fd12:3456:789a::1", Some("Private Network")),
        // 2001:db8::/32 documentation
        ("2001:db8::1", Some("Special Use")),
        // ff00::/8 multicast
        ("ff02::1", Some("Special Use")),
        // Routable addresses must NOT short-circuit
        ("2001:4860:4860::8888", None),
        ("2606:4700::1111", None),
        // Just outside reserved ranges
        ("fe00::1", None),     // below fe80::/10
        ("fec0::1", None),     // above fe80::/10 (old site-local, routable per this filter)
        ("2001:db9::1", None), // adjacent to documentation range
    ];
    for (addr_str, expected) in cases {
        let addr: Ipv6Addr = addr_str.parse().expect("valid IP");
        assert_eq!(
            special_ipv6_name(&addr),
            *expected,
            "wrong classification for {addr_str}"
        );
    }
}

#[tokio::test]
async fn test_lookup_v6_special_ranges_no_network() {
    // Reserved ranges short-circuit before any DNS query, so these run
    // offline. Each yields the typed asn=0 outcome like the v4 path.
    let cache = Arc::new(RwLock::new(crate::asn::cache::AsnCache::new()));
    let cases: &[(&str, &str)] = &[
        ("::1", "Loopback"),
        ("::", "Special Use"),
        ("fe80::1", "Special Use"),
        ("fd00::1", "Private Network"),
        ("2001:db8::1", "Special Use"),
        ("ff02::1", "Special Use"),
    ];
    for (addr_str, expected_name) in cases {
        let addr: Ipv6Addr = addr_str.parse().expect("valid IP");
        let info = lookup_asn_v6_with_cache(addr, &cache)
            .await
            .expect("special range lookup should not fail");
        assert_eq!(info.asn, 0, "ASN should be 0 for {addr_str}");
        assert_eq!(info.name, *expected_name, "wrong name for {addr_str}");
        assert_eq!(info.prefix, format!("{addr}/128"));
    }
}

#[tokio::test]
async fn test_lookup_v6_v4_mapped_defers_to_v4_path() {
    // ::ffff:0:0/96 embeds an IPv4 address; the v4 path's RFC 1918 handling
    // must apply to the embedded address (offline: private range).
    let cache = Arc::new(RwLock::new(crate::asn::cache::AsnCache::new()));
    let addr: Ipv6Addr = "::ffff:192.168.1.1".parse().expect("valid IP");
    let info = lookup_asn_v6_with_cache(addr, &cache)
        .await
        .expect("v4-mapped lookup should not fail");
    assert_eq!(info.asn, 0);
    assert_eq!(info.name, "Private Network");
    // The v4 path answered: prefix is the v4 form, not a /128
    assert_eq!(info.prefix, "192.168.1.1/32");
}

#[tokio::test]
async fn test_lookup_v6_uses_cached_prefix_no_network() {
    // Pre-populate the cache with Google's /32; the lookup must be answered
    // from cache (no DNS involved, so a wrong answer or network dependence
    // would fail deterministically).
    let cache = Arc::new(RwLock::new(crate::asn::cache::AsnCache::new()));
    {
        let cache_write = cache.write().await;
        cache_write.insert_ipv6(
            "2001:4860::/32".parse().expect("valid prefix"),
            AsnInfo {
                asn: 15169,
                prefix: "2001:4860::/32".to_string(),
                country_code: "US".to_string(),
                registry: "arin".to_string(),
                name: "GOOGLE".to_string(),
            },
        );
    }
    let addr: Ipv6Addr = "2001:4860:4860::8888".parse().expect("valid IP");
    let info = lookup_asn_v6_with_cache(addr, &cache)
        .await
        .expect("cached lookup should succeed");
    assert_eq!(info.asn, 15169);
    assert_eq!(info.name, "GOOGLE");
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
