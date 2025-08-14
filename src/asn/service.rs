//! ASN lookup service
//!
//! This module provides a service-oriented API for ASN lookups,
//! abstracting away the caching implementation details.

use super::cache::AsnCache;
use super::lookup::{lookup_asn_with_cache, AsnLookupError};
use crate::traceroute::AsnInfo;
use hickory_resolver::TokioResolver;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use tokio::sync::RwLock;

/// ASN (Autonomous System Number) lookup service
///
/// This service provides ASN information for IPv4 addresses using Team Cymru's
/// whois service. It internally caches results to improve performance.
///
/// # Examples
///
/// ```no_run
/// use ftr::asn::service::AsnLookup;
/// use std::net::IpAddr;
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let asn_service = AsnLookup::new();
///     
///     let ip: IpAddr = "8.8.8.8".parse()?;
///     let asn_info = asn_service.lookup(ip).await?;
///     
///     println!("AS{}: {}", asn_info.asn, asn_info.name);
///     Ok(())
/// }
/// ```
#[derive(Clone, Debug)]
pub struct AsnLookup {
    cache: Arc<RwLock<AsnCache>>,
    resolver: Option<Arc<TokioResolver>>,
}

impl AsnLookup {
    /// Create a new ASN lookup service with default settings
    pub fn new() -> Self {
        Self::with_resolver(None)
    }

    /// Create an ASN lookup service with a specific DNS resolver
    ///
    /// # Arguments
    ///
    /// * `resolver` - Optional DNS resolver to use for queries
    pub fn with_resolver(resolver: Option<Arc<TokioResolver>>) -> Self {
        Self {
            cache: Arc::new(RwLock::new(AsnCache::new())),
            resolver,
        }
    }

    /// Create an ASN lookup service with a pre-populated cache
    ///
    /// # Arguments
    ///
    /// * `cache` - Pre-populated ASN cache
    /// * `resolver` - Optional DNS resolver
    pub fn with_cache(cache: AsnCache, resolver: Option<Arc<TokioResolver>>) -> Self {
        Self {
            cache: Arc::new(RwLock::new(cache)),
            resolver,
        }
    }

    /// Look up ASN information for an IP address
    ///
    /// This method will check the internal cache first, and if not found,
    /// will perform a network lookup using Team Cymru's whois service.
    ///
    /// Note: Currently only IPv4 is supported. IPv6 addresses will return
    /// an error.
    ///
    /// # Arguments
    ///
    /// * `ip` - The IP address to look up
    ///
    /// # Returns
    ///
    /// ASN information including AS number, network prefix, country code,
    /// registry, and organization name.
    pub async fn lookup(&self, ip: IpAddr) -> Result<AsnInfo, AsnLookupError> {
        match ip {
            IpAddr::V4(ipv4) => {
                lookup_asn_with_cache(ipv4, &self.cache, self.resolver.clone()).await
            }
            IpAddr::V6(_) => {
                // IPv6 ASN lookup not yet implemented
                // Return a placeholder for now
                Err(AsnLookupError::NotFound)
            }
        }
    }

    /// Look up ASN information for an IPv4 address
    ///
    /// This is a convenience method that accepts Ipv4Addr directly.
    ///
    /// # Arguments
    ///
    /// * `ip` - The IPv4 address to look up
    pub async fn lookup_ipv4(&self, ip: Ipv4Addr) -> Result<AsnInfo, AsnLookupError> {
        self.lookup(IpAddr::V4(ip)).await
    }

    /// Clear all cached ASN information
    ///
    /// This removes all entries from the internal cache, forcing fresh
    /// lookups for subsequent queries.
    pub async fn clear_cache(&self) {
        let cache = self.cache.write().await;
        cache.clear();
    }

    /// Get statistics about the cache
    ///
    /// Returns information about cache size and hit rate.
    pub async fn cache_stats(&self) -> CacheStats {
        let cache = self.cache.read().await;
        CacheStats {
            entries: cache.len(),
            is_empty: cache.is_empty(),
        }
    }

    /// Check if an IP address is in the cache
    ///
    /// # Arguments
    ///
    /// * `ip` - The IPv4 address to check
    ///
    /// # Returns
    ///
    /// `true` if the IP is cached, `false` otherwise
    pub async fn is_cached(&self, ip: &Ipv4Addr) -> bool {
        let cache = self.cache.read().await;
        cache.get(ip).is_some()
    }
}

impl Default for AsnLookup {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics about the ASN cache
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
    use std::net::IpAddr;

    #[tokio::test]
    async fn test_asn_lookup_service() {
        let service = AsnLookup::new();

        // Test with a private IP
        let private_ip: IpAddr = "192.168.1.1".parse().unwrap();
        let result = service.lookup(private_ip).await;
        assert!(result.is_ok());
        let info = result.unwrap();
        assert_eq!(info.asn, 0);
        assert_eq!(info.name, "Private Network");
    }

    #[tokio::test]
    async fn test_cache_operations() {
        let service = AsnLookup::new();

        // Check initial state
        let stats = service.cache_stats().await;
        assert!(stats.is_empty);

        // Perform a lookup
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let _ = service.lookup(ip).await;

        // Check cache has entry
        // Note: is_cached still uses Ipv4Addr
        if let IpAddr::V4(ipv4) = ip {
            assert!(service.is_cached(&ipv4).await);
        }

        // Clear cache
        service.clear_cache().await;
        let stats = service.cache_stats().await;
        assert!(stats.is_empty);
    }

    #[tokio::test]
    async fn test_public_ip_lookup() {
        let service = AsnLookup::new();

        // Test with Google DNS
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        let result = service.lookup(ip).await;

        if let Ok(info) = result {
            assert_eq!(info.asn, 15169);
            assert!(info.name.contains("GOOGLE"));
        }
        // Allow test to pass even if network is unavailable
    }
}
