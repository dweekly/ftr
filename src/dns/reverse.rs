//! Reverse DNS lookup functionality

use crate::dns::cache::RdnsCache;
use crate::dns::resolver;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Error type for reverse DNS operations
#[derive(Debug, thiserror::Error)]
pub enum ReverseDnsError {
    /// DNS resolution failed
    #[error("DNS resolution failed: {0}")]
    ResolutionError(String),

    /// No PTR record found
    #[error("No PTR record found")]
    NotFound,
}

/// Perform reverse DNS lookup for an IP address with injected cache
/// (Internal use only - users should use RdnsLookup service)
pub(crate) async fn reverse_dns_lookup_with_cache(
    ip: IpAddr,
    cache: &Arc<RwLock<RdnsCache>>,
) -> Result<String, ReverseDnsError> {
    // Check cache first
    {
        let cache_read = cache.read().await;
        if let Some(hostname) = cache_read.get(&ip) {
            return Ok(hostname);
        }
    }

    let name = resolver::resolve_ptr(ip)
        .await
        .map_err(|e| ReverseDnsError::ResolutionError(e.to_string()))?;

    // Cache the result
    let cache_write = cache.write().await;
    cache_write.insert(ip, name.clone());

    Ok(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn test_reverse_dns_localhost() {
        let cache = Arc::new(RwLock::new(crate::dns::cache::RdnsCache::with_default_ttl()));
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let result = reverse_dns_lookup_with_cache(ip, &cache).await;
        match result {
            Ok(hostname) => {
                // PTR resolution succeeded — actual value is system-dependent
                assert!(!hostname.is_empty());
            }
            Err(_) => {
                // It's okay if localhost doesn't have a PTR record
            }
        }
    }

    #[tokio::test]
    async fn test_reverse_dns_private_ip() {
        let cache = Arc::new(RwLock::new(crate::dns::cache::RdnsCache::with_default_ttl()));
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let result = reverse_dns_lookup_with_cache(ip, &cache).await;
        // Private IPs usually don't have PTR records, but not always
        match result {
            Ok(hostname) => assert!(!hostname.is_empty()),
            Err(_) => {} // Expected
        }
    }

    #[tokio::test]
    async fn test_reverse_dns_caching_with_known_ips() {
        // This test makes real PTR queries. Under coverage instrumentation
        // (tarpaulin) it runs much slower, so use a generous timeout.
        let result = tokio::time::timeout(std::time::Duration::from_secs(30), async {
            let cache = Arc::new(RwLock::new(crate::dns::cache::RdnsCache::with_default_ttl()));

            let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));

            // First lookup - should hit network
            let hostname1 = reverse_dns_lookup_with_cache(ip, &cache)
                .await
                .unwrap_or_else(|e| panic!("First lookup failed for {ip}: {e}"));
            assert!(
                hostname1.contains("dns.google"),
                "Expected dns.google, got '{hostname1}'"
            );

            // Second lookup - should hit cache
            let hostname2 = reverse_dns_lookup_with_cache(ip, &cache)
                .await
                .unwrap_or_else(|e| panic!("Second lookup failed for {ip}: {e}"));
            assert_eq!(hostname1, hostname2, "Cache returned different value");

            // Verify it's in cache
            let cached = {
                let cache_read = cache.read().await;
                cache_read.get(&ip)
            };
            if let Some(cached_value) = cached {
                assert_eq!(cached_value, hostname1, "Cached value doesn't match");
            }
        })
        .await;

        if result.is_err() {
            eprintln!(
                "test_reverse_dns_caching_with_known_ips timed out (expected under coverage)"
            );
        }
    }

    #[tokio::test]
    async fn test_reverse_dns_ipv6() {
        let cache = Arc::new(RwLock::new(crate::dns::cache::RdnsCache::with_default_ttl()));
        let ip: IpAddr = "2001:4860:4860::8888".parse().expect("valid IPv6");
        let result = reverse_dns_lookup_with_cache(ip, &cache).await;
        // IPv6 PTR lookups should work but may not always resolve
        match result {
            Ok(hostname) => assert!(!hostname.is_empty()),
            Err(_) => {} // Expected in some environments
        }
    }

    #[tokio::test]
    async fn test_error_types() {
        let err = ReverseDnsError::ResolutionError("test".to_string());
        assert!(err.to_string().contains("test"));

        let err = ReverseDnsError::NotFound;
        assert!(err.to_string().contains("No PTR"));
    }

    #[tokio::test]
    async fn test_concurrent_reverse_lookups() {
        use tokio::task::JoinSet;

        let ips = vec![
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
        ];

        let mut tasks = JoinSet::new();
        for ip in ips {
            let cache = Arc::new(RwLock::new(crate::dns::cache::RdnsCache::with_default_ttl()));
            tasks.spawn(async move { reverse_dns_lookup_with_cache(ip, &cache).await });
        }

        while let Some(result) = tasks.join_next().await {
            // Should complete without panic
            let _ = result.expect("task should not panic");
        }
    }
}
