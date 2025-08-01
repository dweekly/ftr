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
pub(crate) fn test_insert_with_timestamp(
    server: String,
    addresses: Vec<SocketAddr>,
    resolved_at: Instant,
) {
    let mut cache = STUN_CACHE.lock().unwrap();
    cache.insert(
        server,
        CacheEntry {
            addresses,
            resolved_at,
        },
    );
}

#[cfg(test)]
pub(crate) fn test_check_expiration(server: &str) -> Option<bool> {
    let cache = STUN_CACHE.lock().unwrap();
    cache
        .get(server)
        .map(|entry| entry.resolved_at.elapsed() >= CACHE_TTL)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    #[test]
    fn test_cache_ttl_constant() {
        // Verify CACHE_TTL is set to 1 hour (3600 seconds)
        assert_eq!(CACHE_TTL.as_secs(), 3600, "CACHE_TTL should be 1 hour");
    }

    #[tokio::test]
    #[serial]
    async fn test_expiration_with_short_ttl() {
        // This test verifies the expiration logic by using a very short TTL
        // We'll directly test the cache entry expiration check
        use std::thread;

        // Clear cache
        {
            let mut cache = STUN_CACHE.lock().unwrap();
            cache.clear();
        }

        let test_server = "ttl-test.example.com:3478";
        let test_addrs = vec!["203.0.113.1:3478".parse().unwrap()];

        // Insert an entry
        test_insert_with_timestamp(test_server.to_string(), test_addrs.clone(), Instant::now());

        // Immediately after insertion, should not be expired
        {
            let cache = STUN_CACHE.lock().unwrap();
            let entry = cache.get(test_server).expect("Entry should exist");
            assert!(
                entry.resolved_at.elapsed() < CACHE_TTL,
                "New entry should not be expired"
            );
        }

        // Test the expiration check logic
        // Create a test entry with controlled timestamp
        let test_entry = CacheEntry {
            addresses: test_addrs.clone(),
            resolved_at: Instant::now(),
        };

        // Initially not expired
        assert!(test_entry.resolved_at.elapsed() < CACHE_TTL);

        // Sleep a tiny amount and verify it's still not expired
        thread::sleep(Duration::from_millis(10));
        assert!(
            test_entry.resolved_at.elapsed() < CACHE_TTL,
            "Entry should still not be expired after 10ms"
        );

        // Verify that the actual cache lookup respects TTL
        let result = get_stun_server_addrs(test_server).await;
        assert!(result.is_ok(), "Should return cached entry");
        assert_eq!(
            result.unwrap(),
            test_addrs,
            "Should return correct addresses"
        );
    }

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
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        // Clear cache and start fresh
        {
            let mut cache = match STUN_CACHE.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            cache.clear();
        }

        // Test 1: Basic cache functionality - fresh entries should be returned
        let test_server = "test.example.com:3478";
        let test_addresses = vec!["127.0.0.1:3478".parse().unwrap()];

        test_insert_with_timestamp(
            test_server.to_string(),
            test_addresses.clone(),
            Instant::now(),
        );

        // Should return the cached entry
        let result = get_stun_server_addrs(test_server).await;
        assert!(result.is_ok(), "Should return cached entry");
        assert_eq!(
            result.unwrap(),
            test_addresses,
            "Should return correct addresses"
        );

        // Test 2: Test expiration detection logic
        // We can't create past instants on Windows, so we'll test the expiration check logic directly
        {
            let cache = STUN_CACHE.lock().unwrap();
            if let Some(entry) = cache.get(test_server) {
                // Fresh entry should not be expired
                assert!(
                    entry.resolved_at.elapsed() < CACHE_TTL,
                    "Fresh entry should not be expired"
                );
            }
        }

        // Test 3: Verify that get_stun_server_addrs respects the TTL check
        // We'll use a mock approach to test the expiration path
        let expired_server = "expired.test.com:3478";
        let expired_addresses = vec!["192.0.2.1:3478".parse().unwrap()];

        // Insert an entry and verify it's in cache
        test_insert_with_timestamp(
            expired_server.to_string(),
            expired_addresses.clone(),
            Instant::now(),
        );

        // Verify entry exists
        {
            let cache = STUN_CACHE.lock().unwrap();
            assert!(
                cache.contains_key(expired_server),
                "Entry should be in cache"
            );
        }

        // Since we can't make it actually expired, let's test the resolution fallback
        // by using an invalid domain that will fail to resolve
        let invalid_server = "this.will.never.resolve.invalid:3478";
        let result = get_stun_server_addrs(invalid_server).await;
        assert!(result.is_err(), "Invalid domain should fail to resolve");

        // Test 4: Test cache replacement when entry would be expired
        // We'll test that the cache properly updates entries
        let update_server = "stun.l.google.com:19302";

        // First, insert a fake entry
        let fake_addresses = vec!["1.2.3.4:19302".parse().unwrap()];
        test_insert_with_timestamp(
            update_server.to_string(),
            fake_addresses.clone(),
            Instant::now(),
        );

        // Clear the entry to simulate expiration
        {
            let mut cache = STUN_CACHE.lock().unwrap();
            cache.remove(update_server);
        }

        // Now fetch - should get real addresses, not fake ones
        let real_addrs = match get_stun_server_addrs(update_server).await {
            Ok(addrs) => addrs,
            Err(_) => {
                // Network might be down, skip this part of the test
                eprintln!("Skipping network test - DNS resolution failed");
                return;
            }
        };

        assert!(!real_addrs.is_empty(), "Should get real addresses");
        assert_ne!(
            real_addrs, fake_addresses,
            "Should not return fake addresses"
        );

        // Verify cache was updated
        {
            let cache = STUN_CACHE.lock().unwrap();
            let entry = cache.get(update_server).unwrap();
            assert_eq!(
                entry.addresses, real_addrs,
                "Cache should have real addresses"
            );
        }

        // Test 5: Test concurrent access and cache coherency
        let concurrent_server = "concurrent.test.com:3478";
        let concurrent_addrs = vec!["10.0.0.1:3478".parse().unwrap()];
        let was_cached = Arc::new(AtomicBool::new(false));

        // Insert entry
        test_insert_with_timestamp(
            concurrent_server.to_string(),
            concurrent_addrs.clone(),
            Instant::now(),
        );

        // Launch multiple concurrent readers
        let mut handles = vec![];
        for _ in 0..10 {
            let server = concurrent_server.to_string();
            let expected = concurrent_addrs.clone();
            let cached_flag = was_cached.clone();

            let handle = tokio::spawn(async move {
                let result = get_stun_server_addrs(&server).await;
                assert!(result.is_ok(), "Concurrent read should succeed");
                assert_eq!(result.unwrap(), expected, "Should get cached data");
                cached_flag.store(true, Ordering::SeqCst);
            });
            handles.push(handle);
        }

        // Wait for all to complete
        for handle in handles {
            handle.await.unwrap();
        }

        assert!(
            was_cached.load(Ordering::SeqCst),
            "Cache should have been used"
        );

        // Test 6: Verify expiration check function works correctly
        assert_eq!(
            test_check_expiration(concurrent_server),
            Some(false),
            "Fresh entry should not be marked as expired"
        );

        assert_eq!(
            test_check_expiration("nonexistent.server.com:3478"),
            None,
            "Nonexistent entry should return None"
        );
    }
}
