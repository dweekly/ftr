//! ASN lookup service
//!
//! This module provides a service-oriented API for ASN lookups,
//! abstracting away the caching implementation details.

use super::cache::AsnCache;
use super::lookup::{lookup_asn_with_cache, AsnLookupError};
use crate::traceroute::AsnInfo;
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
}

impl AsnLookup {
    /// Create a new ASN lookup service with default settings
    pub fn new() -> Self {
        Self {
            cache: Arc::new(RwLock::new(AsnCache::new())),
        }
    }

    /// Create an ASN lookup service with a pre-populated cache
    pub fn with_cache(cache: AsnCache) -> Self {
        Self {
            cache: Arc::new(RwLock::new(cache)),
        }
    }

    /// Look up ASN information for an IP address
    pub async fn lookup(&self, ip: IpAddr) -> Result<AsnInfo, AsnLookupError> {
        match ip {
            IpAddr::V4(ipv4) => lookup_asn_with_cache(ipv4, &self.cache).await,
            IpAddr::V6(_) => Err(AsnLookupError::NotFound),
        }
    }

    /// Look up ASN information for an IPv4 address
    pub async fn lookup_ipv4(&self, ip: Ipv4Addr) -> Result<AsnInfo, AsnLookupError> {
        self.lookup(IpAddr::V4(ip)).await
    }

    /// Clear all cached ASN information
    pub async fn clear_cache(&self) {
        let cache = self.cache.write().await;
        cache.clear();
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
        let private_ip: IpAddr = "192.168.1.1".parse().expect("valid IP");
        let result = service.lookup(private_ip).await;
        assert!(result.is_ok());
        let info = result.expect("should succeed");
        assert_eq!(info.asn, 0);
        assert_eq!(info.name, "Private Network");
    }

    #[tokio::test]
    async fn test_cache_operations() {
        let service = AsnLookup::new();
        let stats = service.cache_stats().await;
        assert!(stats.is_empty);

        let ip: IpAddr = "10.0.0.1".parse().expect("valid IP");
        let _ = service.lookup(ip).await;

        if let IpAddr::V4(ipv4) = ip {
            assert!(service.is_cached(&ipv4).await);
        }

        service.clear_cache().await;
        let stats = service.cache_stats().await;
        assert!(stats.is_empty);
    }

    #[tokio::test]
    async fn test_public_ip_lookup() {
        let service = AsnLookup::new();
        let ip: IpAddr = "8.8.8.8".parse().expect("valid IP");
        let result = service.lookup(ip).await;
        if let Ok(info) = result {
            assert_eq!(info.asn, 15169);
            assert!(info.name.contains("GOOGLE"));
        }
    }
}
