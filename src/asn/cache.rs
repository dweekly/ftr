//! ASN lookup caching functionality

use crate::traceroute::AsnInfo;
use ip_network::Ipv4Network;
use ip_network_table::IpNetworkTable;
use ipnet::Ipv4Net;
use std::sync::{Arc, RwLock};

/// Thread-safe cache for ASN lookups by CIDR prefix
pub struct AsnCache {
    cache: Arc<RwLock<IpNetworkTable<AsnInfo>>>,
}

impl std::fmt::Debug for AsnCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AsnCache").finish()
    }
}

impl Default for AsnCache {
    fn default() -> Self {
        Self::new()
    }
}

impl AsnCache {
    /// Create a new empty cache
    pub fn new() -> Self {
        Self {
            cache: Arc::new(RwLock::new(IpNetworkTable::new())),
        }
    }

    /// Look up an IP address in the cache
    pub fn get(&self, ip: &std::net::Ipv4Addr) -> Option<AsnInfo> {
        let cache = self.cache.read().expect("rwlock poisoned");
        cache
            .longest_match(*ip)
            .map(|(_, asn_info)| asn_info.clone())
    }

    /// Insert an ASN info entry into the cache
    pub fn insert(&self, prefix: Ipv4Net, asn_info: AsnInfo) {
        let mut cache = self.cache.write().expect("rwlock poisoned");
        match Ipv4Network::new(prefix.addr(), prefix.prefix_len()) {
            Ok(ipv4_network) => {
                cache.insert(ipv4_network, asn_info);
            }
            Err(e) => {
                // This should not happen as we are converting from a valid Ipv4Net
                eprintln!("Error converting Ipv4Net to Ipv4Network: {}", e);
            }
        }
    }

    /// Get the number of entries in the cache
    pub fn len(&self) -> usize {
        let cache = self.cache.read().expect("rwlock poisoned");
        let (ipv4_len, ipv6_len) = cache.len();
        ipv4_len + ipv6_len
    }

    /// Check if the cache is empty
    pub fn is_empty(&self) -> bool {
        let cache = self.cache.read().expect("rwlock poisoned");
        cache.is_empty()
    }

    /// Clear all entries from the cache
    pub fn clear(&self) {
        let mut cache = self.cache.write().expect("rwlock poisoned");
        *cache = IpNetworkTable::new();
    }
}

/// Global ASN cache instance
pub static ASN_CACHE: std::sync::LazyLock<AsnCache> = std::sync::LazyLock::new(AsnCache::new);

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_asn_cache() {
        let cache = AsnCache::new();
        assert!(cache.is_empty());

        // Create test ASN info
        let asn_info = AsnInfo {
            asn: 13335,
            prefix: "104.16.0.0/12".to_string(),
            country_code: "US".to_string(),
            registry: "ARIN".to_string(),
            name: "CLOUDFLARENET".to_string(),
        };

        // Insert into cache
        let prefix: Ipv4Net = "104.16.0.0/12".parse().unwrap();
        cache.insert(prefix, asn_info.clone());

        assert_eq!(cache.len(), 1);
        assert!(!cache.is_empty());

        // Test lookup - IP within the prefix
        let ip: Ipv4Addr = "104.16.1.1".parse().unwrap();
        let result = cache.get(&ip);
        assert!(result.is_some());
        assert_eq!(result.unwrap().asn, 13335);

        // Test lookup - IP outside the prefix
        let ip: Ipv4Addr = "8.8.8.8".parse().unwrap();
        let result = cache.get(&ip);
        assert!(result.is_none());

        // Test clear
        cache.clear();
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_overlapping_prefixes() {
        let cache = AsnCache::new();
        let specific_prefix = "192.168.1.0/24".parse().unwrap();
        let specific_info = AsnInfo {
            asn: 1,
            prefix: "192.168.1.0/24".to_string(),
            country_code: "US".to_string(),
            registry: "ARIN".to_string(),
            name: "Specific".to_string(),
        };
        cache.insert(specific_prefix, specific_info);

        let broader_prefix = "192.168.0.0/16".parse().unwrap();
        let broader_info = AsnInfo {
            asn: 2,
            prefix: "192.168.0.0/16".to_string(),
            country_code: "US".to_string(),
            registry: "ARIN".to_string(),
            name: "Broader".to_string(),
        };
        cache.insert(broader_prefix, broader_info);

        // Should match the most specific prefix
        let ip: Ipv4Addr = "192.168.1.1".parse().unwrap();
        let result = cache.get(&ip);
        assert!(result.is_some());
        assert_eq!(result.unwrap().asn, 1);
    }
}
