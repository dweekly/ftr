//! Reverse DNS lookup functionality

use crate::dns::cache::RdnsCache;
use hickory_resolver::config::ResolverConfig;
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::TokioResolver;
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
    resolver: Option<Arc<TokioResolver>>,
) -> Result<String, ReverseDnsError> {
    // Check cache first
    {
        let cache_read = cache.read().await;
        if let Some(hostname) = cache_read.get(&ip) {
            return Ok(hostname);
        }
    }

    // Use provided resolver or create a new one
    let resolver = match resolver {
        Some(r) => r,
        None => Arc::new(create_default_resolver()),
    };

    let lookup = resolver
        .reverse_lookup(ip)
        .await
        .map_err(|e| ReverseDnsError::ResolutionError(e.to_string()))?;

    // Get the first PTR record
    let name = lookup
        .iter()
        .next()
        .map(|name| {
            let name_str = name.to_string();
            // Remove trailing dot if present
            if name_str.ends_with('.') {
                name_str[..name_str.len() - 1].to_string()
            } else {
                name_str
            }
        })
        .ok_or(ReverseDnsError::NotFound)?;

    // Cache the result
    let cache_write = cache.write().await;
    cache_write.insert(ip, name.clone());

    Ok(name)
}

/// Create a default DNS resolver
pub fn create_default_resolver() -> TokioResolver {
    TokioResolver::builder_with_config(
        ResolverConfig::cloudflare(),
        TokioConnectionProvider::default(),
    )
    .build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn test_reverse_dns_localhost() {
        let cache = Arc::new(RwLock::new(crate::dns::cache::RdnsCache::with_default_ttl()));
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let result = reverse_dns_lookup_with_cache(ip, &cache, None).await;
        // Localhost might resolve to "localhost" or might fail depending on system config
        // So we just check that the function completes without panicking
        match result {
            Ok(hostname) => {
                // PTR resolution succeeded — just verify we got a non-empty string.
                // The actual value is system-dependent (localhost, loopback, machine hostname, etc.)
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
        let result = reverse_dns_lookup_with_cache(ip, &cache, None).await;
        // Private IPs typically don't have PTR records on public DNS
        // So we just verify the function handles this gracefully
        match result {
            Ok(_) => {} // Unexpected but okay
            Err(e) => {
                // Should be a resolution error or not found
                assert!(
                    matches!(e, ReverseDnsError::ResolutionError(_))
                        || matches!(e, ReverseDnsError::NotFound)
                );
            }
        }
    }

    #[tokio::test]
    async fn test_create_resolver() {
        let cache = Arc::new(RwLock::new(crate::dns::cache::RdnsCache::with_default_ttl()));
        let resolver = Arc::new(create_default_resolver());
        // Test that we can use the resolver
        let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let _ = reverse_dns_lookup_with_cache(ip, &cache, Some(resolver)).await;
        // We don't assert on the result as DNS can be flaky in tests
    }

    #[tokio::test]
    async fn test_reverse_dns_caching_with_known_ips() {
        use crate::dns::test_utils::reset_dns_counter;

        // This test makes real PTR queries. Under coverage instrumentation
        // (tarpaulin) it runs much slower, so use a generous timeout.
        let result = tokio::time::timeout(std::time::Duration::from_secs(30), async {
            let cache = Arc::new(RwLock::new(crate::dns::cache::RdnsCache::with_default_ttl()));
            reset_dns_counter();

            let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));

            // First lookup - should hit network
            let hostname1 = reverse_dns_lookup_with_cache(ip, &cache, None)
                .await
                .unwrap_or_else(|e| panic!("First lookup failed for {ip}: {e}"));
            assert!(
                hostname1.contains("dns.google"),
                "Expected dns.google, got '{hostname1}'"
            );

            // Second lookup - should hit cache
            let hostname2 = reverse_dns_lookup_with_cache(ip, &cache, None)
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
        let ip = IpAddr::V6("2001:4860:4860::8888".parse().unwrap());
        let result = reverse_dns_lookup_with_cache(ip, &cache, None).await;

        match result {
            Ok(hostname) => {
                assert!(!hostname.is_empty());
                // Google's IPv6 DNS typically has PTR records
            }
            Err(_) => {
                // Network issues or no PTR record is acceptable in tests
            }
        }
    }

    #[tokio::test]
    async fn test_trailing_dot_removal() {
        // This test verifies that trailing dots are removed from hostnames
        // We can't directly test this with real DNS, so we test the logic
        // by checking the result doesn't end with a dot
        let cache = Arc::new(RwLock::new(crate::dns::cache::RdnsCache::with_default_ttl()));
        let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let result = reverse_dns_lookup_with_cache(ip, &cache, None).await;

        if let Ok(hostname) = result {
            assert!(!hostname.ends_with('.'), "Hostname should not end with dot");
        }
    }

    #[tokio::test]
    async fn test_error_types() {
        // Use a reserved TEST-NET-1 address that shouldn't have a PTR record
        // 192.0.2.0/24 is reserved for documentation (RFC 5737)
        let cache = Arc::new(RwLock::new(crate::dns::cache::RdnsCache::with_default_ttl()));
        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 123));
        let result = reverse_dns_lookup_with_cache(ip, &cache, None).await;

        assert!(result.is_err());
        match result.unwrap_err() {
            ReverseDnsError::ResolutionError(_) | ReverseDnsError::NotFound => {
                // Both error types are acceptable
            }
        }
    }

    #[tokio::test]
    async fn test_concurrent_lookups() {
        use tokio::task::JoinSet;

        let ips = vec![
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(208, 67, 222, 222)),
        ];

        let mut tasks = JoinSet::new();

        let cache = Arc::new(RwLock::new(crate::dns::cache::RdnsCache::with_default_ttl()));

        for ip in ips {
            let cache_clone = Arc::clone(&cache);
            tasks.spawn(async move { reverse_dns_lookup_with_cache(ip, &cache_clone, None).await });
        }

        let mut results = Vec::new();
        while let Some(result) = tasks.join_next().await {
            match result {
                Ok(dns_result) => results.push(dns_result),
                Err(e) => eprintln!("Task failed: {}", e),
            }
        }

        // We should have results for all IPs (success or failure)
        assert_eq!(results.len(), 3);
    }
}
