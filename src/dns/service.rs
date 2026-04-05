//! Reverse DNS lookup service
//!
//! This module provides a service-oriented API for reverse DNS lookups,
//! abstracting away the caching implementation details.

use super::cache::RdnsCache;
use super::reverse::{reverse_dns_lookup_with_cache, ReverseDnsError};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

/// Reverse DNS lookup service
///
/// This service provides hostname resolution for IP addresses.
/// It internally caches results with a configurable TTL to improve performance.
///
/// # Examples
///
/// ```no_run
/// use ftr::dns::service::RdnsLookup;
/// use std::net::IpAddr;
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let rdns_service = RdnsLookup::new();
///
///     let ip: IpAddr = "8.8.8.8".parse()?;
///     let hostname = rdns_service.lookup(ip).await?;
///
///     println!("{} -> {}", ip, hostname);
///     Ok(())
/// }
/// ```
#[derive(Clone, Debug)]
pub struct RdnsLookup {
    cache: Arc<RwLock<RdnsCache>>,
}

impl RdnsLookup {
    /// Create a new reverse DNS lookup service with default TTL (1 hour)
    pub fn new() -> Self {
        Self::with_ttl(Duration::from_secs(3600))
    }

    /// Create a reverse DNS lookup service with custom cache TTL
    pub fn with_ttl(ttl: Duration) -> Self {
        Self {
            cache: Arc::new(RwLock::new(RdnsCache::new(ttl))),
        }
    }

    /// Create a reverse DNS lookup service with a pre-populated cache
    pub fn with_cache(cache: RdnsCache) -> Self {
        Self {
            cache: Arc::new(RwLock::new(cache)),
        }
    }

    /// Look up the hostname for an IP address
    pub async fn lookup(&self, ip: IpAddr) -> Result<String, ReverseDnsError> {
        reverse_dns_lookup_with_cache(ip, &self.cache).await
    }

    /// Clear all cached reverse DNS entries
    pub async fn clear_cache(&self) {
        let cache = self.cache.write().await;
        cache.clear();
    }

    /// Remove expired entries from the cache
    pub async fn evict_expired(&self) {
        let cache = self.cache.write().await;
        cache.evict_expired();
    }

    /// Get statistics about the cache
    pub async fn cache_stats(&self) -> CacheStats {
        let cache = self.cache.read().await;
        CacheStats {
            entries: cache.len(),
            is_empty: cache.is_empty(),
        }
    }

    /// Check if an IP address is in the cache
    pub async fn is_cached(&self, ip: &IpAddr) -> bool {
        let cache = self.cache.read().await;
        cache.get(ip).is_some()
    }
}

impl Default for RdnsLookup {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics about the reverse DNS cache
#[derive(Debug, Clone)]
pub struct CacheStats {
    /// Number of entries in the cache
    pub entries: usize,
    /// Whether the cache is empty
    pub is_empty: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn test_rdns_lookup_service() {
        let service = RdnsLookup::new();
        let localhost = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let result = service.lookup(localhost).await;
        if let Ok(hostname) = result {
            assert!(!hostname.is_empty());
        }
    }

    #[tokio::test]
    async fn test_cache_operations() {
        let service = RdnsLookup::with_ttl(Duration::from_secs(60));
        let stats = service.cache_stats().await;
        assert!(stats.is_empty);

        let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let _ = service.lookup(ip).await;

        if service.is_cached(&ip).await {
            let stats = service.cache_stats().await;
            assert_eq!(stats.entries, 1);
        }

        service.clear_cache().await;
        let stats = service.cache_stats().await;
        assert!(stats.is_empty);
    }

    #[tokio::test]
    async fn test_custom_ttl() {
        let service = RdnsLookup::with_ttl(Duration::from_millis(50));
        let ip = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let _ = service.lookup(ip).await;

        tokio::time::sleep(Duration::from_millis(60)).await;
        service.evict_expired().await;

        let stats = service.cache_stats().await;
        assert!(stats.is_empty);
    }
}
