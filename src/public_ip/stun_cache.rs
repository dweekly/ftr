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
        let cache = STUN_CACHE.lock().expect("STUN cache lock poisoned");
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
        let mut cache = STUN_CACHE.lock().expect("STUN cache lock poisoned");
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

    #[tokio::test]
    async fn test_stun_cache() {
        // First call should resolve
        let start = Instant::now();
        let addrs1 = get_stun_server_addrs("stun.l.google.com:19302")
            .await
            .unwrap();
        let first_duration = start.elapsed();
        assert!(!addrs1.is_empty());

        // Second call should be cached (much faster)
        let start = Instant::now();
        let addrs2 = get_stun_server_addrs("stun.l.google.com:19302")
            .await
            .unwrap();
        let cached_duration = start.elapsed();

        assert_eq!(addrs1, addrs2);
        // Cached lookup should be at least 10x faster
        assert!(cached_duration < first_duration / 10);
    }
}
