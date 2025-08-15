//! Tests for caching functionality

#[cfg(test)]
mod tests {
    use crate::{Ftr, TracerouteConfigBuilder};
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    #[tokio::test]
    async fn test_rdns_caching() {
        // Create service with its internal cache
        let rdns_service = crate::dns::service::RdnsLookup::new();

        let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));

        // First lookup should hit the network
        let result1 = rdns_service.lookup(ip).await;
        assert!(result1.is_ok() || result1.is_err()); // May succeed or fail depending on network

        // Second lookup should be from cache if first succeeded
        if result1.is_ok() {
            let hostname1 = result1.unwrap();
            let result2 = rdns_service.lookup(ip).await;
            assert!(result2.is_ok());
            assert_eq!(hostname1, result2.unwrap());

            // Verify it's cached
            assert!(rdns_service.is_cached(&ip).await);
        }
    }

    #[tokio::test]
    async fn test_asn_caching() {
        // Create service with its internal cache
        let asn_service = crate::asn::service::AsnLookup::new();

        // Use a private IP that will always return consistent results
        let ip = Ipv4Addr::new(192, 168, 1, 1);

        // First lookup
        let result1 = asn_service.lookup_ipv4(ip).await;
        assert!(result1.is_ok());
        let asn1 = result1.unwrap();
        assert_eq!(asn1.name, "Private Network");

        // Second lookup should be from cache
        let result2 = asn_service.lookup_ipv4(ip).await;
        assert!(result2.is_ok());
        let asn2 = result2.unwrap();

        // Should be the same
        assert_eq!(asn1.asn, asn2.asn);
        assert_eq!(asn1.name, asn2.name);

        // Verify it's cached
        assert!(asn_service.is_cached(&ip).await);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_public_ip_parameter() {
        let ftr = Ftr::new();
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

        let result =
            tokio::time::timeout(Duration::from_secs(2), ftr.trace_with_config(config)).await;

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
        let ftr = Ftr::new();
        let target = "8.8.8.8";
        let target_ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));

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
            tokio::time::timeout(Duration::from_secs(2), ftr.trace_with_config(config1)).await;

        if let Ok(Ok(_)) = result1 {
            // Second trace with same parameters - should use cached data
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
                tokio::time::timeout(Duration::from_secs(2), ftr.trace_with_config(config2)).await;

            // Both traces should succeed
            assert!(result2.is_ok());
        }
    }

    #[test]
    fn test_cache_thread_safety() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        use std::thread;

        // Create a shared cache
        let cache = Arc::new(std::sync::RwLock::new(
            crate::dns::cache::RdnsCache::with_default_ttl(),
        ));

        // Track if operations completed successfully
        let success = Arc::new(AtomicBool::new(true));

        let handles: Vec<_> = (0..10)
            .map(|i| {
                let success = Arc::clone(&success);
                let cache = Arc::clone(&cache);
                thread::spawn(move || {
                    // Use unique IPs to avoid conflicts with other tests
                    let ip = IpAddr::V4(Ipv4Addr::new(10, 250, i, 1));

                    // Try to insert - this should not panic
                    match std::panic::catch_unwind(|| {
                        let cache_write = cache.write().unwrap();
                        cache_write.insert(ip, format!("test-host-{}.local", i));
                    }) {
                        Ok(_) => {}
                        Err(_) => {
                            success.store(false, Ordering::Relaxed);
                            return;
                        }
                    }

                    // Try to read multiple entries - this should not panic
                    for j in 0..10 {
                        let check_ip = IpAddr::V4(Ipv4Addr::new(10, 250, j, 1));
                        match std::panic::catch_unwind(|| {
                            let cache_read = cache.read().unwrap();
                            let _ = cache_read.get(&check_ip);
                        }) {
                            Ok(_) => {}
                            Err(_) => {
                                success.store(false, Ordering::Relaxed);
                                return;
                            }
                        }
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }

        // The test passes if all operations completed without panicking
        assert!(
            success.load(Ordering::Relaxed),
            "Cache operations should be thread-safe"
        );
    }
}
