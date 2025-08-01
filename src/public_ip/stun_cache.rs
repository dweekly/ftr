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
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Cache entry for a resolved STUN server
#[derive(Debug, Clone)]
struct CacheEntry {
    addresses: Vec<SocketAddr>,
    resolved_at: Instant,
}

/// How long to cache STUN server addresses (1 hour)
const CACHE_TTL: Duration = Duration::from_secs(3600);

/// Global cache for STUN server addresses
static STUN_CACHE: Lazy<Mutex<HashMap<String, CacheEntry>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// Get cached STUN server addresses or resolve and cache them
pub async fn get_stun_server_addrs(server: &str) -> std::io::Result<Vec<SocketAddr>> {
    // Check cache first
    {
        let cache = match STUN_CACHE.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                // Recover from poisoned mutex by taking the data
                poisoned.into_inner()
            }
        };
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
        let mut cache = match STUN_CACHE.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                // Recover from poisoned mutex by taking the data
                poisoned.into_inner()
            }
        };
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
        let _ = get_stun_server_addrs(server).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    #[tokio::test]
    #[serial]
    async fn test_stun_cache() {
        // Clear cache to ensure clean test state
        {
            let mut cache = match STUN_CACHE.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            cache.clear();
        }

        // Verify cache starts empty
        {
            let cache = STUN_CACHE.lock().unwrap();
            assert_eq!(cache.len(), 0, "Cache should start empty");
        }

        // Use a test server
        let test_server = "stun.l.google.com:19302";

        // First call should resolve and populate cache
        let addrs1 = match get_stun_server_addrs(test_server).await {
            Ok(addrs) => addrs,
            Err(e) => {
                eprintln!("DNS resolution failed in test environment: {}", e);
                return; // Skip test if DNS fails
            }
        };
        assert!(!addrs1.is_empty(), "Should resolve at least one address");

        // Verify the cache now contains exactly one entry
        {
            let cache = STUN_CACHE.lock().unwrap();
            assert_eq!(cache.len(), 1, "Cache should contain exactly 1 entry");
            assert!(
                cache.contains_key(test_server),
                "Cache should contain the test server"
            );

            let cached_entry = cache.get(test_server).unwrap();
            assert_eq!(
                cached_entry.addresses, addrs1,
                "Cached addresses should match returned addresses"
            );

            // Verify the timestamp is recent
            assert!(
                cached_entry.resolved_at.elapsed() < Duration::from_secs(1),
                "Cache entry should be fresh"
            );
        }

        // Second call should return cached data
        let addrs2 = get_stun_server_addrs(test_server).await.unwrap();

        assert_eq!(
            addrs1, addrs2,
            "Second call should return identical cached result"
        );

        // Verify the cache entry hasn't changed (still the same data)
        {
            let cache = STUN_CACHE.lock().unwrap();
            let cached_entry = cache.get(test_server).unwrap();
            assert_eq!(
                cached_entry.addresses, addrs1,
                "Cache should still contain the same addresses"
            );
        }

        // Verify cache still has exactly one entry
        {
            let cache = STUN_CACHE.lock().unwrap();
            assert_eq!(cache.len(), 1, "Cache should still have exactly 1 entry");
        }

        // Test with a different server
        let test_server2 = "stun1.l.google.com:19302";
        let addrs3 = match get_stun_server_addrs(test_server2).await {
            Ok(addrs) => addrs,
            Err(_) => return, // Skip if DNS fails
        };
        assert!(!addrs3.is_empty(), "Should resolve second server");

        // Note: stun.l.google.com and stun1.l.google.com might resolve to the same IPs
        // The important thing is that both are cached independently

        // Both entries should be in cache now
        {
            let cache = STUN_CACHE.lock().unwrap();
            assert_eq!(cache.len(), 2, "Cache should contain exactly 2 entries");
            assert!(cache.contains_key(test_server));
            assert!(cache.contains_key(test_server2));

            // Verify each entry has the correct data
            assert_eq!(cache.get(test_server).unwrap().addresses, addrs1);
            assert_eq!(cache.get(test_server2).unwrap().addresses, addrs3);
        }

        // Third call to first server should still return cached result
        let addrs4 = get_stun_server_addrs(test_server).await.unwrap();
        assert_eq!(
            addrs4, addrs1,
            "Third call should return same cached result"
        );

        // Test that cache prevents network lookups for invalid domains
        // Pre-populate cache with a fake entry for an invalid domain
        let fake_server = "this.will.never.resolve.invalid:3478";
        let fake_addresses = vec!["192.0.2.1:3478".parse().unwrap()]; // TEST-NET-1
        {
            let mut cache = STUN_CACHE.lock().unwrap();
            cache.insert(
                fake_server.to_string(),
                CacheEntry {
                    addresses: fake_addresses.clone(),
                    resolved_at: Instant::now(),
                },
            );
        }

        // This should succeed because it uses the cache, not DNS
        let cached_fake = get_stun_server_addrs(fake_server).await.unwrap();
        assert_eq!(
            cached_fake, fake_addresses,
            "Should return cached data without attempting DNS lookup"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_stun_cache_error_handling() {
        // Clear cache to ensure clean test state
        {
            let mut cache = match STUN_CACHE.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            cache.clear();
        }

        // Test with invalid server name
        let invalid_server = "this.definitely.does.not.exist.invalid:12345";
        let result = get_stun_server_addrs(invalid_server).await;
        assert!(result.is_err(), "Invalid server should return error");

        // Error results should not be cached
        {
            let cache = match STUN_CACHE.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            assert!(
                !cache.contains_key(invalid_server),
                "Failed lookups should not be cached"
            );
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_stun_cache_ttl() {
        // Clear cache
        {
            let mut cache = match STUN_CACHE.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            cache.clear();
        }

        // Insert an entry with expired TTL
        let test_server = "test.example.com:3478";
        let old_addresses = vec!["127.0.0.1:3478".parse().unwrap()];

        {
            let mut cache = STUN_CACHE.lock().unwrap();
            cache.insert(
                test_server.to_string(),
                CacheEntry {
                    addresses: old_addresses.clone(),
                    resolved_at: Instant::now() - Duration::from_secs(7200), // 2 hours ago (expired)
                },
            );
            assert_eq!(cache.len(), 1, "Cache should have the expired entry");
        }

        // Try to get the expired server - should NOT return the expired entry
        // Instead it should try to resolve fresh
        let result = get_stun_server_addrs(test_server).await;

        // The lookup will fail (invalid domain), but that's OK
        // The important thing is it didn't return the expired entry
        assert!(result.is_err(), "Should fail to resolve invalid domain");

        // Cache should still have just the one entry (not updated since resolution failed)
        {
            let cache = STUN_CACHE.lock().unwrap();
            assert_eq!(cache.len(), 1, "Failed lookups don't update cache");
        }

        // Now test with a valid server but expired entry
        let valid_server = "stun.l.google.com:19302";
        let fake_old_address = vec!["1.2.3.4:19302".parse().unwrap()];

        {
            let mut cache = STUN_CACHE.lock().unwrap();
            cache.clear();
            cache.insert(
                valid_server.to_string(),
                CacheEntry {
                    addresses: fake_old_address.clone(),
                    resolved_at: Instant::now() - Duration::from_secs(7200), // Expired
                },
            );
        }

        // Resolve should give us fresh data, not the expired fake address
        let fresh_addrs = match get_stun_server_addrs(valid_server).await {
            Ok(addrs) => addrs,
            Err(_) => return, // Skip if network is down
        };

        assert!(!fresh_addrs.is_empty(), "Should get fresh addresses");
        assert_ne!(
            fresh_addrs, fake_old_address,
            "Should not return the expired fake address"
        );

        // Cache should be updated with fresh data
        {
            let cache = STUN_CACHE.lock().unwrap();
            let entry = cache.get(valid_server).unwrap();
            assert_eq!(entry.addresses, fresh_addrs, "Cache should have fresh data");
            assert!(
                entry.resolved_at.elapsed() < Duration::from_secs(1),
                "Cache entry should be fresh"
            );
        }

        // Test that non-expired entries are returned from cache
        let recent_server = "recent.test.com:3478";
        let recent_addresses = vec!["5.6.7.8:3478".parse().unwrap()];

        {
            let mut cache = STUN_CACHE.lock().unwrap();
            cache.insert(
                recent_server.to_string(),
                CacheEntry {
                    addresses: recent_addresses.clone(),
                    resolved_at: Instant::now() - Duration::from_secs(60), // 1 minute ago (not expired)
                },
            );
        }

        // This should return from cache without trying to resolve
        // We know this because recent.test.com doesn't exist
        let cached_addrs = get_stun_server_addrs(recent_server).await.unwrap();
        assert_eq!(
            cached_addrs, recent_addresses,
            "Should return non-expired entry from cache"
        );
    }
}
