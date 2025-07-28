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

        // Create test ASN info - note: ASN format without "AS" prefix
        let asn_info = AsnInfo {
            asn: "13335".to_string(),
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
        assert_eq!(result.unwrap().asn, "13335");

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
        // Clear any existing data
        ASN_CACHE.clear();
        assert!(ASN_CACHE.is_empty());

        // Insert test data - note: ASN format without "AS" prefix
        let asn_info = AsnInfo {
            asn: "15169".to_string(),
            prefix: "8.8.8.0/24".to_string(),
            country_code: "US".to_string(),
            registry: "ARIN".to_string(),
            name: "GOOGLE".to_string(),
        };

        let prefix: Ipv4Net = "8.8.8.0/24".parse().unwrap();
        ASN_CACHE.insert(prefix, asn_info);

        // Verify insertion
        let ip: Ipv4Addr = "8.8.8.8".parse().unwrap();
        let result = ASN_CACHE.get(&ip);
        assert!(result.is_some());
        assert_eq!(result.unwrap().name, "GOOGLE");
    }
}
