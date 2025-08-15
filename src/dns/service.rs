//! Reverse DNS lookup service
//!
//! This module provides a service-oriented API for reverse DNS lookups,
//! abstracting away the caching implementation details.

use super::cache::RdnsCache;
use super::reverse::{reverse_dns_lookup_with_cache, ReverseDnsError};
use hickory_resolver::TokioResolver;
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
    resolver: Option<Arc<TokioResolver>>,
}

impl RdnsLookup {
    /// Create a new reverse DNS lookup service with default TTL (1 hour)
    pub fn new() -> Self {
        Self::with_ttl(Duration::from_secs(3600))
    }

    /// Create a reverse DNS lookup service with custom cache TTL
    ///
    /// # Arguments
    ///
    /// * `ttl` - Time-to-live for cached entries
    pub fn with_ttl(ttl: Duration) -> Self {
        Self {
            cache: Arc::new(RwLock::new(RdnsCache::new(ttl))),
            resolver: None,
        }
    }

    /// Set a specific DNS resolver for this service
    ///
    /// # Arguments
    ///
    /// * `resolver` - DNS resolver to use for queries
    pub fn with_resolver(mut self, resolver: Arc<TokioResolver>) -> Self {
        self.resolver = Some(resolver);
        self
    }

    /// Create a reverse DNS lookup service with a pre-populated cache
    ///
    /// # Arguments
    ///
    /// * `cache` - Pre-populated reverse DNS cache
    /// * `resolver` - Optional DNS resolver
    pub fn with_cache(cache: RdnsCache, resolver: Option<Arc<TokioResolver>>) -> Self {
        Self {
            cache: Arc::new(RwLock::new(cache)),
            resolver,
        }
    }

    /// Look up the hostname for an IP address
    ///
    /// This method will check the internal cache first, and if not found
    /// or expired, will perform a DNS PTR lookup.
    ///
    /// # Arguments
    ///
    /// * `ip` - The IP address to look up
    ///
    /// # Returns
    ///
    /// The hostname associated with the IP address, or an error if
    /// the lookup fails or no PTR record exists.
    pub async fn lookup(&self, ip: IpAddr) -> Result<String, ReverseDnsError> {
        reverse_dns_lookup_with_cache(ip, &self.cache, self.resolver.clone()).await
    }

    /// Clear all cached reverse DNS entries
    ///
    /// This removes all entries from the internal cache, forcing fresh
    /// lookups for subsequent queries.
    pub async fn clear_cache(&self) {
        let cache = self.cache.write().await;
        cache.clear();
    }

    /// Remove expired entries from the cache
    ///
    /// This method cleans up entries that have exceeded their TTL.
    /// It's called automatically during lookups but can be triggered
    /// manually if needed.
    pub async fn evict_expired(&self) {
        let cache = self.cache.write().await;
        cache.evict_expired();
    }

    /// Get statistics about the cache
    ///
    /// Returns information about cache size.
    pub async fn cache_stats(&self) -> CacheStats {
        let cache = self.cache.read().await;
        CacheStats {
            entries: cache.len(),
            is_empty: cache.is_empty(),
        }
    }

    /// Check if an IP address is in the cache
    ///
    /// Note: This checks for existence only, not whether the entry is expired.
    ///
    /// # Arguments
    ///
    /// * `ip` - The IP address to check
    ///
    /// # Returns
    ///
    /// `true` if the IP is cached, `false` otherwise
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

        // Test with localhost
        let localhost = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let result = service.lookup(localhost).await;

        // Localhost might resolve or might not, depending on system
        if let Ok(hostname) = result {
            assert!(!hostname.is_empty());
        }
    }

    #[tokio::test]
    async fn test_cache_operations() {
        let service = RdnsLookup::with_ttl(Duration::from_secs(60));

        // Check initial state
        let stats = service.cache_stats().await;
        assert!(stats.is_empty);

        // Perform a lookup on a public DNS server
        let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let _ = service.lookup(ip).await;

        // If lookup succeeded, check cache
        if service.is_cached(&ip).await {
            let stats = service.cache_stats().await;
            assert_eq!(stats.entries, 1);
        }

        // Clear cache
        service.clear_cache().await;
        let stats = service.cache_stats().await;
        assert!(stats.is_empty);
    }

    #[tokio::test]
    async fn test_custom_ttl() {
        // Create service with very short TTL
        let service = RdnsLookup::with_ttl(Duration::from_millis(50));

        let ip = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let _ = service.lookup(ip).await;

        // Wait for expiration
        tokio::time::sleep(Duration::from_millis(60)).await;

        // Evict expired entries
        service.evict_expired().await;

        // Cache should be empty after eviction
        let stats = service.cache_stats().await;
        assert!(stats.is_empty);
    }

    #[tokio::test]
    async fn test_ipv6_lookup() {
        let service = RdnsLookup::new();

        // Test with Google's IPv6 DNS
        let ipv6 = IpAddr::V6("2001:4860:4860::8888".parse().unwrap());
        let result = service.lookup(ipv6).await;

        // IPv6 reverse DNS might not always be available
        if let Ok(hostname) = result {
            assert!(!hostname.is_empty());
        }
    }
}
