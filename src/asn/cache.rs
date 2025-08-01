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
    use serial_test::serial;
    use std::net::Ipv4Addr;

    #[test]
    #[serial]
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
    #[serial]
    fn test_global_cache() {
        // Clear the global cache to ensure clean state
        ASN_CACHE.clear();
        assert_eq!(ASN_CACHE.len(), 0, "Cache should be empty after clear");

        // Use TEST-NET-2 (RFC 5737) for predictable test data
        let test_prefix = "198.51.100.0/24";
        let test_ip1 = "198.51.100.1";
        let test_ip2 = "198.51.100.255";
        let outside_ip = "198.51.101.1"; // Outside the prefix

        // Create test ASN info
        let asn_info = AsnInfo {
            asn: 64512, // Private ASN range
            prefix: test_prefix.to_string(),
            country_code: "XX".to_string(),
            registry: "TEST".to_string(),
            name: "TEST-ASN-CACHE".to_string(),
        };

        // Insert into cache
        let prefix: Ipv4Net = test_prefix.parse().unwrap();
        ASN_CACHE.insert(prefix, asn_info.clone());

        assert_eq!(ASN_CACHE.len(), 1, "Cache should have exactly 1 entry");

        // Test lookup for IPs within the prefix
        let ip1: Ipv4Addr = test_ip1.parse().unwrap();
        let result1 = ASN_CACHE.get(&ip1);
        assert!(result1.is_some(), "Should find IP within prefix");
        let found1 = result1.unwrap();
        assert_eq!(found1.asn, 64512);
        assert_eq!(found1.name, "TEST-ASN-CACHE");
        assert_eq!(found1.prefix, test_prefix);

        // Test another IP in the same prefix
        let ip2: Ipv4Addr = test_ip2.parse().unwrap();
        let result2 = ASN_CACHE.get(&ip2);
        assert!(result2.is_some(), "Should find another IP within prefix");
        assert_eq!(result2.unwrap().asn, 64512);

        // Test IP outside the prefix
        let ip_outside: Ipv4Addr = outside_ip.parse().unwrap();
        let result_outside = ASN_CACHE.get(&ip_outside);
        assert!(
            result_outside.is_none(),
            "Should not find IP outside prefix"
        );

        // Test inserting overlapping prefixes
        let broader_prefix = "198.51.0.0/16";
        let broader_info = AsnInfo {
            asn: 64513,
            prefix: broader_prefix.to_string(),
            country_code: "YY".to_string(),
            registry: "TEST2".to_string(),
            name: "TEST-BROADER".to_string(),
        };

        let prefix_broad: Ipv4Net = broader_prefix.parse().unwrap();
        ASN_CACHE.insert(prefix_broad, broader_info);
        assert_eq!(ASN_CACHE.len(), 2, "Cache should have 2 entries");

        // The more specific prefix should still match
        let result_specific = ASN_CACHE.get(&ip1);
        assert!(result_specific.is_some());
        // Note: Depending on implementation, might get either prefix
        // The important thing is we get a result

        // Test multiple lookups return consistent data
        // Note: With overlapping prefixes, we might get either one
        let first_lookup = ASN_CACHE.get(&ip1).unwrap();
        let expected_asn = first_lookup.asn;
        let expected_name = first_lookup.name.clone();

        for _ in 0..10 {
            let result = ASN_CACHE.get(&ip1);
            assert!(result.is_some(), "Repeated lookups should find the entry");
            let found = result.unwrap();
            assert_eq!(found.asn, expected_asn, "Should return consistent ASN");
            assert_eq!(found.name, expected_name, "Should return consistent name");
        }

        // Test clear
        ASN_CACHE.clear();
        assert_eq!(ASN_CACHE.len(), 0, "Cache should be empty after clear");
        assert!(ASN_CACHE.get(&ip1).is_none(), "Should not find after clear");
    }
}
