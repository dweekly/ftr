//! STUN server address caching
//!
//! This module caches resolved STUN server addresses to avoid repeated
//! DNS lookups, which can add 10-50ms of latency.
//!
//! Optimization: By caching the IP addresses of STUN servers like
//! stun.l.google.com, we avoid DNS resolution on every run. This is
//! especially important since STUN is used for fast public IP detection
//! (replacing slow HTTPS calls).

use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Cache entry for a resolved STUN server
#[derive(Debug, Clone)]
struct CacheEntry {
    addresses: Vec<SocketAddr>,
    resolved_at: Instant,
}

/// How long to cache STUN server addresses (1 hour)
const CACHE_TTL: Duration = Duration::from_secs(3600);

/// Thread-safe cache for STUN server addresses
#[derive(Debug)]
pub struct StunCache {
    cache: Arc<Mutex<HashMap<String, CacheEntry>>>,
}

impl Default for StunCache {
    fn default() -> Self {
        Self::new()
    }
}

impl StunCache {
    /// Create a new empty cache
    pub fn new() -> Self {
        Self {
            cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Get cached STUN server addresses or resolve and cache them
    pub async fn get_stun_server_addrs(&self, server: &str) -> std::io::Result<Vec<SocketAddr>> {
        // Check cache first
        {
            let cache = self.cache.lock().expect("mutex poisoned");
            if let Some(entry) = cache.get(server) {
                if entry.resolved_at.elapsed() < CACHE_TTL {
                    return Ok(entry.addresses.clone());
                }
            }
        }

        // Not in cache or expired, resolve it
        let addresses: Vec<SocketAddr> = tokio::net::lookup_host(server).await?.collect();

        if addresses.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "No addresses found for STUN server",
            ));
        }

        // Cache the result
        {
            let mut cache = self.cache.lock().expect("mutex poisoned");
            cache.insert(
                server.to_string(),
                CacheEntry {
                    addresses: addresses.clone(),
                    resolved_at: Instant::now(),
                },
            );
        }

        Ok(addresses)
    }

    /// Clear all entries from the cache
    pub fn clear(&self) {
        let mut cache = self.cache.lock().expect("mutex poisoned");
        cache.clear();
    }
}

/// Global cache for STUN server addresses
pub static STUN_CACHE: Lazy<StunCache> = Lazy::new(StunCache::new);

/// Pre-warm the cache with common STUN servers
pub async fn prewarm_stun_cache() {
    let mut servers = vec![
        "stun.l.google.com:19302",
        "stun1.l.google.com:19302",
        "stun2.l.google.com:19302",
    ];

    // Add custom STUN server if provided
    if let Ok(custom_server) = std::env::var("FTR_STUN_SERVER") {
        servers.insert(0, Box::leak(custom_server.into_boxed_str()));
    }

    for server in &servers {
        let _ = STUN_CACHE.get_stun_server_addrs(server).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_ttl_constant() {
        // Verify CACHE_TTL is set to 1 hour (3600 seconds)
        assert_eq!(CACHE_TTL.as_secs(), 3600, "CACHE_TTL should be 1 hour");
    }

    #[tokio::test]
    async fn test_stun_cache() {
        let cache = StunCache::new();
        let test_server = "stun.l.google.com:19302";

        // First call should resolve and populate cache
        let addrs1 = match cache.get_stun_server_addrs(test_server).await {
            Ok(addrs) => addrs,
            Err(e) => {
                eprintln!("DNS resolution failed in test environment: {}", e);
                return; // Skip test if DNS fails
            }
        };
        assert!(!addrs1.is_empty(), "Should resolve at least one address");

        // Second call should return cached data
        let addrs2 = cache.get_stun_server_addrs(test_server).await.unwrap();
        assert_eq!(
            addrs1, addrs2,
            "Second call should return identical cached result"
        );
    }

    #[tokio::test]
    async fn test_stun_cache_error_handling() {
        let cache = StunCache::new();
        let invalid_server = "this.definitely.does.not.exist.invalid:12345";
        let result = cache.get_stun_server_addrs(invalid_server).await;
        assert!(result.is_err(), "Invalid server should return error");
    }

    #[tokio::test]
    async fn test_stun_cache_ttl() {
        let cache = StunCache::new();
        let test_server = "test.example.com:3478";
        let test_addresses = vec!["127.0.0.1:3478".parse().unwrap()];

        // First, verify a fresh entry is returned from cache
        {
            let mut cache_lock = cache.cache.lock().unwrap();
            cache_lock.insert(
                test_server.to_string(),
                CacheEntry {
                    addresses: test_addresses.clone(),
                    resolved_at: Instant::now(),
                },
            );
        }

        // Should return the cached entry
        let result = cache.get_stun_server_addrs(test_server).await;
        assert!(result.is_ok(), "Should return cached entry");
        assert_eq!(
            result.unwrap(),
            test_addresses,
            "Should return correct addresses"
        );

        // Now test expiration logic
        // We'll create an expired entry by using the earliest Instant we can safely create
        // The key insight: we just need any instant that's > CACHE_TTL ago
        {
            let mut cache_lock = cache.cache.lock().unwrap();

            // Try to create an instant that's CACHE_TTL + 1 second in the past
            // If that fails (e.g., on Windows with recent boot), we'll just clear the cache
            // to force re-resolution, which achieves the same test goal
            if let Some(expired_time) =
                Instant::now().checked_sub(CACHE_TTL + Duration::from_secs(1))
            {
                // We can create an expired timestamp - use it
                cache_lock.insert(
                    test_server.to_string(),
                    CacheEntry {
                        addresses: test_addresses.clone(),
                        resolved_at: expired_time,
                    },
                );
            } else {
                // Can't create an old enough timestamp on this platform
                // Just remove the entry to force re-resolution
                cache_lock.remove(test_server);
            }
        }

        // Either way (expired or missing), it should try to resolve, which will fail
        let result = cache.get_stun_server_addrs(test_server).await;
        assert!(
            result.is_err(),
            "Should attempt re-resolution for expired/missing entry"
        );
    }
}
