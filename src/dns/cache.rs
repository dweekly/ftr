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
    use std::net::Ipv4Addr;
    use std::thread;

    #[test]
    fn test_rdns_cache() {
        let cache = RdnsCache::new(Duration::from_secs(60));
        assert!(cache.is_empty());

        // Insert entry
        let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        cache.insert(ip, "dns.google".to_string());

        assert_eq!(cache.len(), 1);
        assert!(!cache.is_empty());

        // Test lookup
        let result = cache.get(&ip);
        assert!(result.is_some());
        assert_eq!(result.unwrap(), "dns.google");

        // Test non-existent lookup
        let other_ip = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let result = cache.get(&other_ip);
        assert!(result.is_none());

        // Test clear
        cache.clear();
        assert!(cache.is_empty());
    }

    #[test]
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
