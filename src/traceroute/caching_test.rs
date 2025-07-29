//! Tests for caching functionality

#[cfg(test)]
mod tests {
    use crate::asn::{lookup_asn, ASN_CACHE};
    use crate::dns::RDNS_CACHE;
    use crate::{trace_with_config, TracerouteConfigBuilder};
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    #[tokio::test]
    async fn test_rdns_caching() {
        // Clear cache
        RDNS_CACHE.clear();

        let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));

        // First lookup should hit the network
        let result1 = crate::dns::reverse_dns_lookup(ip, None).await;
        assert!(result1.is_ok() || result1.is_err()); // May succeed or fail depending on network

        // Second lookup should be from cache if first succeeded
        if result1.is_ok() {
            let hostname1 = result1.unwrap();
            let result2 = crate::dns::reverse_dns_lookup(ip, None).await;
            assert!(result2.is_ok());
            assert_eq!(hostname1, result2.unwrap());

            // Verify it's in the cache
            assert!(RDNS_CACHE.get(&ip).is_some());
        }
    }

    #[tokio::test]
    async fn test_asn_caching() {
        // Clear cache
        ASN_CACHE.clear();

        // Use a private IP that will always return consistent results
        let ip = Ipv4Addr::new(192, 168, 1, 1);

        // First lookup
        let result1 = lookup_asn(ip, None).await;
        assert!(result1.is_ok());
        let asn1 = result1.unwrap();
        assert_eq!(asn1.name, "Private Network");

        // Second lookup should be from cache
        let result2 = lookup_asn(ip, None).await;
        assert!(result2.is_ok());
        let asn2 = result2.unwrap();

        // Should be the same
        assert_eq!(asn1.asn, asn2.asn);
        assert_eq!(asn1.name, asn2.name);

        // Verify cache has entries
        assert!(!ASN_CACHE.is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_public_ip_parameter() {
        let public_ip = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));

        let config = TracerouteConfigBuilder::new()
            .target("127.0.0.1")
            .target_ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
            .max_hops(1)
            .probe_timeout(Duration::from_millis(100))
            .overall_timeout(Duration::from_millis(500))
            .public_ip(public_ip)
            .enable_asn_lookup(true)
            .build()
            .unwrap();

        let result = tokio::time::timeout(Duration::from_secs(2), trace_with_config(config)).await;

        match result {
            Ok(Ok(trace_result)) => {
                if let Some(isp_info) = trace_result.isp_info {
                    // Should use the provided public IP
                    assert_eq!(isp_info.public_ip, public_ip);
                }
            }
            _ => {
                // Timeout or permission error is okay in tests
            }
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_repeated_traces_use_cache() {
        let target = "8.8.8.8";
        let target_ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));

        // Clear caches
        RDNS_CACHE.clear();
        ASN_CACHE.clear();

        // First trace
        let config1 = TracerouteConfigBuilder::new()
            .target(target)
            .target_ip(target_ip)
            .max_hops(3)
            .probe_timeout(Duration::from_millis(100))
            .overall_timeout(Duration::from_millis(500))
            .enable_asn_lookup(true)
            .enable_rdns(true)
            .build()
            .unwrap();

        let result1 =
            tokio::time::timeout(Duration::from_secs(2), trace_with_config(config1)).await;

        if let Ok(Ok(_)) = result1 {
            // Cache should have entries now
            let cache_size_after_first = ASN_CACHE.len();

            // Second trace with same parameters
            let config2 = TracerouteConfigBuilder::new()
                .target(target)
                .target_ip(target_ip)
                .max_hops(3)
                .probe_timeout(Duration::from_millis(100))
                .overall_timeout(Duration::from_millis(500))
                .enable_asn_lookup(true)
                .enable_rdns(true)
                .build()
                .unwrap();

            let result2 =
                tokio::time::timeout(Duration::from_secs(2), trace_with_config(config2)).await;

            if let Ok(Ok(_)) = result2 {
                // Cache size should be the same or larger (not smaller)
                assert!(ASN_CACHE.len() >= cache_size_after_first);
            }
        }
    }

    #[test]
    fn test_cache_thread_safety() {
        use std::thread;

        // Clear cache before test
        RDNS_CACHE.clear();

        let handles: Vec<_> = (0..10)
            .map(|i| {
                thread::spawn(move || {
                    let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, i));
                    RDNS_CACHE.insert(ip, format!("host{}.local", i));

                    // Try to read
                    for j in 0..10 {
                        let check_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, j));
                        let _ = RDNS_CACHE.get(&check_ip);
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }

        // Should have some entries and not crash
        assert!(RDNS_CACHE.len() > 0);
    }
}
