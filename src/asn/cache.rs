//! ASN lookup caching functionality

use crate::traceroute::AsnInfo;
use ipnet::Ipv4Net;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Thread-safe cache for ASN lookups by CIDR prefix
pub struct AsnCache {
    cache: Arc<Mutex<HashMap<Ipv4Net, AsnInfo>>>,
}

impl AsnCache {
    /// Create a new empty cache
    pub fn new() -> Self {
        Self {
            cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Look up an IP address in the cache
    pub fn get(&self, ip: &std::net::Ipv4Addr) -> Option<AsnInfo> {
        let cache = self.cache.lock().expect("mutex poisoned");
        for (prefix, asn_info) in cache.iter() {
            if prefix.contains(ip) {
                return Some(asn_info.clone());
            }
        }
        None
    }

    /// Insert an ASN info entry into the cache
    pub fn insert(&self, prefix: Ipv4Net, asn_info: AsnInfo) {
        let mut cache = self.cache.lock().expect("mutex poisoned");
        cache.insert(prefix, asn_info);
    }

    /// Get the number of entries in the cache
    pub fn len(&self) -> usize {
        let cache = self.cache.lock().expect("mutex poisoned");
        cache.len()
    }

    /// Check if the cache is empty
    pub fn is_empty(&self) -> bool {
        let cache = self.cache.lock().expect("mutex poisoned");
        cache.is_empty()
    }

    /// Clear all entries from the cache
    pub fn clear(&self) {
        let mut cache = self.cache.lock().expect("mutex poisoned");
        cache.clear();
    }
}

impl Default for AsnCache {
    fn default() -> Self {
        Self::new()
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
    fn test_global_cache() {
        // Use a unique prefix that won't conflict with other tests
        let unique_prefix = "8.8.4.0/24";
        let test_ip = "8.8.4.4";

        // Insert test data
        let asn_info = AsnInfo {
            asn: 15169,
            prefix: unique_prefix.to_string(),
            country_code: "US".to_string(),
            registry: "ARIN".to_string(),
            name: "GOOGLE-TEST".to_string(),
        };

        let prefix: Ipv4Net = unique_prefix.parse().unwrap();
        ASN_CACHE.insert(prefix, asn_info.clone());

        // Verify insertion
        let ip: Ipv4Addr = test_ip.parse().unwrap();
        let result = ASN_CACHE.get(&ip);

        // The cache might contain other entries from parallel tests,
        // so we just verify our entry exists
        assert!(result.is_some(), "Failed to find entry for {}", test_ip);
        let found = result.unwrap();
        assert_eq!(found.asn, 15169);
        assert_eq!(found.name, "GOOGLE-TEST");
    }
}
