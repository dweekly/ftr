//! Reverse DNS lookup caching functionality

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Cache entry with timestamp
#[derive(Debug, Clone)]
struct CacheEntry {
    hostname: String,
    inserted_at: Instant,
}

/// Thread-safe cache for reverse DNS lookups
pub struct RdnsCache {
    cache: Arc<Mutex<HashMap<IpAddr, CacheEntry>>>,
    ttl: Duration,
}

impl RdnsCache {
    /// Create a new cache with specified TTL
    pub fn new(ttl: Duration) -> Self {
        Self {
            cache: Arc::new(Mutex::new(HashMap::new())),
            ttl,
        }
    }

    /// Create a new cache with default TTL (1 hour)
    pub fn with_default_ttl() -> Self {
        Self::new(Duration::from_secs(3600))
    }

    /// Look up an IP address in the cache
    pub fn get(&self, ip: &IpAddr) -> Option<String> {
        let mut cache = self.cache.lock().expect("mutex poisoned");

        // Check if entry exists and is not expired
        if let Some(entry) = cache.get(ip) {
            if entry.inserted_at.elapsed() < self.ttl {
                return Some(entry.hostname.clone());
            } else {
                // Remove expired entry
                cache.remove(ip);
            }
        }
        None
    }

    /// Insert a hostname into the cache
    pub fn insert(&self, ip: IpAddr, hostname: String) {
        let mut cache = self.cache.lock().expect("mutex poisoned");
        cache.insert(
            ip,
            CacheEntry {
                hostname,
                inserted_at: Instant::now(),
            },
        );
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

    /// Remove expired entries from the cache
    pub fn evict_expired(&self) {
        let mut cache = self.cache.lock().expect("mutex poisoned");
        let now = Instant::now();
        cache.retain(|_, entry| now.duration_since(entry.inserted_at) < self.ttl);
    }
}

impl Default for RdnsCache {
    fn default() -> Self {
        Self::with_default_ttl()
    }
}

/// Global rDNS cache instance
pub static RDNS_CACHE: std::sync::LazyLock<RdnsCache> =
    std::sync::LazyLock::new(RdnsCache::with_default_ttl);

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use std::net::Ipv4Addr;
    use std::thread;

    #[test]
    #[serial]
    fn test_rdns_cache() {
        let cache = RdnsCache::new(Duration::from_secs(60));

        // Test initial state
        assert!(cache.is_empty(), "Cache should start empty");
        assert_eq!(cache.len(), 0, "Initial cache size should be 0");

        // Test insertion
        let ip1 = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let hostname1 = "dns.google".to_string();
        cache.insert(ip1, hostname1.clone());

        assert_eq!(cache.len(), 1, "Cache should have 1 entry after insert");
        assert!(!cache.is_empty(), "Cache should not be empty after insert");

        // Test retrieval
        let retrieved = cache.get(&ip1);
        assert!(retrieved.is_some(), "Should find inserted entry");
        assert_eq!(
            retrieved.unwrap(),
            hostname1,
            "Should retrieve correct hostname"
        );

        // Test multiple lookups return consistent data
        for _ in 0..10 {
            let result = cache.get(&ip1);
            assert_eq!(
                result.unwrap(),
                hostname1,
                "Cache should return consistent data"
            );
        }

        // Test multiple entries
        let ip2 = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let hostname2 = "one.one.one.one".to_string();
        cache.insert(ip2, hostname2.clone());
        assert_eq!(cache.len(), 2, "Cache should have 2 entries");

        // Verify both entries exist and are correct
        assert_eq!(cache.get(&ip1).unwrap(), hostname1);
        assert_eq!(cache.get(&ip2).unwrap(), hostname2);

        // Test missing entry
        let ip3 = IpAddr::V4(Ipv4Addr::new(4, 4, 4, 4));
        assert!(
            cache.get(&ip3).is_none(),
            "Should return None for missing entry"
        );

        // Test update/overwrite
        let new_hostname1 = "dns.google.com".to_string();
        cache.insert(ip1, new_hostname1.clone());
        assert_eq!(
            cache.get(&ip1).unwrap(),
            new_hostname1,
            "Should return updated hostname"
        );
        assert_eq!(cache.len(), 2, "Size shouldn't change on update");

        // Test IPv6
        let ipv6 = IpAddr::V6("2001:4860:4860::8888".parse().unwrap());
        let hostname_v6 = "dns.google.ipv6".to_string();
        cache.insert(ipv6, hostname_v6.clone());
        assert_eq!(cache.len(), 3, "Should handle IPv6 addresses");
        assert_eq!(cache.get(&ipv6).unwrap(), hostname_v6);

        // Test clear
        cache.clear();
        assert!(cache.is_empty(), "Cache should be empty after clear");
        assert_eq!(cache.len(), 0, "Size should be 0 after clear");
        assert!(cache.get(&ip1).is_none(), "Should return None after clear");
        assert!(cache.get(&ip2).is_none(), "Should return None after clear");
    }

    #[test]
    #[serial]
    fn test_cache_expiration() {
        let cache = RdnsCache::new(Duration::from_millis(50));
        let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));

        cache.insert(ip, "dns.google".to_string());

        // Should exist immediately
        assert!(cache.get(&ip).is_some());

        // Wait for expiration
        thread::sleep(Duration::from_millis(60));

        // Should be expired and removed
        assert!(cache.get(&ip).is_none());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    #[serial]
    fn test_evict_expired() {
        let cache = RdnsCache::new(Duration::from_millis(50));

        // Insert multiple entries
        cache.insert(
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            "dns1.google".to_string(),
        );
        cache.insert(
            IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4)),
            "dns2.google".to_string(),
        );

        assert_eq!(cache.len(), 2);

        // Wait for expiration
        thread::sleep(Duration::from_millis(60));

        // Evict expired entries
        cache.evict_expired();
        assert_eq!(cache.len(), 0);
    }

    #[test]
    #[serial]
    fn test_global_cache() {
        // Clear any existing data
        RDNS_CACHE.clear();
        assert!(RDNS_CACHE.is_empty());

        // Insert test data
        let ip = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        RDNS_CACHE.insert(ip, "one.one.one.one".to_string());

        // Verify insertion
        let result = RDNS_CACHE.get(&ip);
        assert!(result.is_some());
        assert_eq!(result.unwrap(), "one.one.one.one");
    }
}
