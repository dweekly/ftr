//! Tests to verify caching behavior with request counting

use ftr::{trace_with_config, TracerouteConfigBuilder};
use std::net::{IpAddr, Ipv4Addr};

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

            // Cache sizes should not decrease (can increase slightly due to public IP lookup)
            assert!(
                ftr::dns::RDNS_CACHE.len() >= dns_cache_size,
                "DNS cache size should not decrease (was {}, now {})",
                dns_cache_size,
                ftr::dns::RDNS_CACHE.len()
            );
            // ASN cache might grow by 1-2 entries due to public IP detection
            let asn_cache_growth = ftr::asn::ASN_CACHE.len() - asn_cache_size;
            assert!(
                asn_cache_growth <= 2,
                "ASN cache should not grow significantly (grew by {} entries, from {} to {})",
                asn_cache_growth,
                asn_cache_size,
                ftr::asn::ASN_CACHE.len()
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
        }
    }
}

#[tokio::test]
async fn test_public_ip_caching_in_traces() {
    // Skip on GitHub Actions Windows/Linux - unreliable ICMP
    if std::env::var("GITHUB_ACTIONS").is_ok() {
        let os = std::env::consts::OS;
        if os == "windows" || os == "linux" {
            eprintln!("Skipping test on GitHub Actions {} (unreliable ICMP)", os);
            return;
        }
    }

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
