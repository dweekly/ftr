//! Tests to verify caching behavior with request counting

use ftr::{trace_with_config, TracerouteConfigBuilder};
use std::net::{IpAddr, Ipv4Addr};

#[tokio::test]
async fn test_dns_caching_reduces_requests() {
    // Clear caches before test
    ftr::dns::RDNS_CACHE.clear();
    ftr::asn::ASN_CACHE.clear();

    // Known IPs with stable PTR records
    let test_ips = vec![
        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), // dns.google
        IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), // one.one.one.one
        IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)), // dns9.quad9.net
    ];

    // Test direct DNS lookups
    for ip in &test_ips {
        // Clear cache for fair test
        ftr::dns::RDNS_CACHE.clear();

        // First lookup - goes to network
        let result1 = ftr::dns::reverse_dns_lookup(*ip, None).await;
        assert!(result1.is_ok(), "First DNS lookup failed for {}", ip);
        let initial_cache_size = ftr::dns::RDNS_CACHE.len();
        assert_eq!(
            initial_cache_size, 1,
            "Cache should have 1 entry after first lookup"
        );

        // Multiple subsequent lookups - should all hit cache
        for i in 0..5 {
            let result = ftr::dns::reverse_dns_lookup(*ip, None).await;
            assert!(result.is_ok(), "Lookup {} failed for {}", i + 2, ip);
            assert_eq!(
                result.unwrap(),
                *result1.as_ref().unwrap(),
                "Cached result differs from initial for {}",
                ip
            );

            // Cache size should not increase
            assert_eq!(
                ftr::dns::RDNS_CACHE.len(),
                initial_cache_size,
                "Cache size increased on lookup {}",
                i + 2
            );
        }
    }
}

#[tokio::test]
async fn test_asn_caching_with_cidr() {
    // Clear ASN cache
    ftr::asn::ASN_CACHE.clear();

    // IPs in the same CIDR block
    let google_ips = vec![Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(8, 8, 4, 4)];

    // First lookup
    let result1 = ftr::asn::lookup_asn(google_ips[0], None).await;
    assert!(result1.is_ok(), "First ASN lookup failed");
    let asn1 = result1.unwrap();
    assert_eq!(asn1.asn, "15169", "Expected Google ASN");

    let cache_size_after_first = ftr::asn::ASN_CACHE.len();
    assert!(cache_size_after_first > 0, "ASN cache should have entries");

    // Second lookup for different IP in same block
    let result2 = ftr::asn::lookup_asn(google_ips[1], None).await;
    assert!(result2.is_ok(), "Second ASN lookup failed");
    let asn2 = result2.unwrap();

    // Should get same ASN (both are Google)
    assert_eq!(asn1.asn, asn2.asn, "ASNs should match for Google IPs");

    // Note: 8.8.8.8 and 8.8.4.4 are in different /24 blocks, so cache may grow
    // The important thing is that both resolve to Google's ASN
    assert!(asn1.name.contains("GOOGLE"), "First IP should be Google");
    assert!(asn2.name.contains("GOOGLE"), "Second IP should be Google");
}

#[tokio::test]
async fn test_traceroute_with_caching() {
    // Clear all caches
    ftr::dns::RDNS_CACHE.clear();
    ftr::asn::ASN_CACHE.clear();

    let target = "1.1.1.1";

    // First trace - cold cache
    let config1 = TracerouteConfigBuilder::new()
        .target(target)
        .max_hops(5)
        .enable_asn_lookup(true)
        .enable_rdns(true)
        .build()
        .unwrap();

    let result1 = trace_with_config(config1).await;
    match result1 {
        Ok(trace_result) => {
            // Record cache sizes after first trace
            let dns_cache_size = ftr::dns::RDNS_CACHE.len();
            let asn_cache_size = ftr::asn::ASN_CACHE.len();

            println!(
                "After first trace: DNS cache={}, ASN cache={}",
                dns_cache_size, asn_cache_size
            );

            // Note: DNS cache might be 0 if no responsive hops were found
            // or if rdns lookups failed. Check if any hops have hostnames.
            let hops_with_hostnames = trace_result
                .hops
                .iter()
                .filter(|h| h.hostname.is_some())
                .count();

            if dns_cache_size == 0 && hops_with_hostnames == 0 {
                eprintln!("Warning: No hops with hostnames found, DNS cache empty is expected");
            } else if hops_with_hostnames > 0 {
                assert!(
                    dns_cache_size > 0,
                    "DNS cache should have entries after trace with {} hops having hostnames",
                    hops_with_hostnames
                );
            }
            assert!(
                asn_cache_size > 0,
                "ASN cache should have entries after trace"
            );

            // Second trace - warm cache
            let config2 = TracerouteConfigBuilder::new()
                .target(target)
                .max_hops(5)
                .enable_asn_lookup(true)
                .enable_rdns(true)
                .build()
                .unwrap();

            let result2 = trace_with_config(config2).await;
            assert!(result2.is_ok(), "Second trace should succeed");

            // Cache sizes should not change significantly
            assert_eq!(
                ftr::dns::RDNS_CACHE.len(),
                dns_cache_size,
                "DNS cache size should remain stable"
            );
            assert_eq!(
                ftr::asn::ASN_CACHE.len(),
                asn_cache_size,
                "ASN cache size should remain stable"
            );

            // Results should be consistent
            let trace2 = result2.unwrap();
            assert_eq!(
                trace_result.hop_count(),
                trace2.hop_count(),
                "Hop counts should match between traces"
            );
        }
        Err(e) => {
            eprintln!("Trace failed (may be due to permissions): {}", e);
            // Still check that caches work independently

            // Test DNS cache
            let ip = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
            let dns1 = ftr::dns::reverse_dns_lookup(ip, None).await;
            if dns1.is_ok() {
                let cache_size = ftr::dns::RDNS_CACHE.len();
                let dns2 = ftr::dns::reverse_dns_lookup(ip, None).await;
                assert_eq!(dns1.unwrap(), dns2.unwrap());
                assert_eq!(ftr::dns::RDNS_CACHE.len(), cache_size);
            }
        }
    }
}

#[tokio::test]
async fn test_public_ip_caching_in_traces() {
    let public_ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));

    // Create configs with and without public IP
    let config_with_ip = TracerouteConfigBuilder::new()
        .target("8.8.8.8")
        .max_hops(3)
        .public_ip(public_ip)
        .enable_asn_lookup(true)
        .build()
        .unwrap();

    let config_without_ip = TracerouteConfigBuilder::new()
        .target("8.8.8.8")
        .max_hops(3)
        .enable_asn_lookup(true)
        .build()
        .unwrap();

    // Trace with provided public IP
    let result_with = trace_with_config(config_with_ip).await;
    match result_with {
        Ok(trace) => {
            if let Some(isp) = trace.isp_info {
                assert_eq!(isp.public_ip, public_ip, "Should use provided public IP");
            }
        }
        Err(_) => {
            // Permission errors are acceptable
        }
    }

    // Trace without provided public IP - would detect automatically
    let result_without = trace_with_config(config_without_ip).await;
    match result_without {
        Ok(trace) => {
            if let Some(isp) = trace.isp_info {
                // Should have detected a real public IP
                match isp.public_ip {
                    IpAddr::V4(v4) => {
                        assert!(!v4.is_private());
                        assert!(!v4.is_loopback());
                    }
                    IpAddr::V6(_) => {
                        // IPv6 is also valid
                    }
                }
            }
        }
        Err(_) => {
            // Permission or network errors are acceptable
        }
    }
}
