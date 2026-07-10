//! STUN client service for public IP detection
//!
//! This module provides a service-oriented API for STUN-based public IP detection,
//! abstracting away the server address caching implementation details.

use super::stun::{get_public_ip_stun_with_servers_and_cache, StunError, STUN_SERVERS};
use super::stun_cache::StunCache;
use super::PublicIpError;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

/// STUN client for public IP detection
///
/// This service uses STUN (Session Traversal Utilities for NAT) protocol
/// to detect the public IP address of the current machine. It internally
/// caches STUN server addresses to avoid repeated DNS lookups.
///
/// # Examples
///
/// ```no_run
/// use ftr::public_ip::service::StunClient;
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let stun = StunClient::new();
///     
///     let public_ip = stun.get_public_ip().await?;
///     println!("Public IP: {}", public_ip);
///     
///     Ok(())
/// }
/// ```
#[derive(Clone, Debug)]
pub struct StunClient {
    cache: Arc<RwLock<StunCache>>,
    servers: Vec<String>,
    timeout: Duration,
    verbose: u8,
}

impl StunClient {
    /// Create a new STUN client with the default servers
    ///
    /// Uses the well-known public servers in [`STUN_SERVERS`]
    /// (Google primary and backup, Cloudflare fallback).
    pub fn new() -> Self {
        Self::with_servers(STUN_SERVERS.iter().map(|s| (*s).to_string()).collect())
    }

    /// Create a STUN client with custom servers
    ///
    /// Servers are tried in order: the first is the primary and the rest
    /// are fallbacks used only if earlier servers fail.
    ///
    /// # Arguments
    ///
    /// * `servers` - List of STUN server addresses in "host:port" format
    pub fn with_servers(servers: Vec<String>) -> Self {
        Self {
            cache: Arc::new(RwLock::new(StunCache::new())),
            servers,
            timeout: Duration::from_millis(500),
            verbose: 0,
        }
    }

    /// Set the timeout for STUN requests
    ///
    /// # Arguments
    ///
    /// * `timeout` - Maximum time to wait for a STUN response
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set the verbosity level for STUN diagnostics
    ///
    /// Levels 2 and above print per-server diagnostics to stderr.
    /// This replaces the former FTR_VERBOSE environment variable lookup.
    ///
    /// # Arguments
    ///
    /// * `verbose` - Verbosity level (0 = silent)
    pub fn with_verbose(mut self, verbose: u8) -> Self {
        self.verbose = verbose;
        self
    }

    /// Create a STUN client with a pre-populated cache
    ///
    /// # Arguments
    ///
    /// * `cache` - Pre-populated STUN server cache
    /// * `servers` - List of STUN server addresses
    pub fn with_cache(cache: StunCache, servers: Vec<String>) -> Self {
        Self {
            cache: Arc::new(RwLock::new(cache)),
            servers,
            timeout: Duration::from_millis(500),
            verbose: 0,
        }
    }

    /// Get the public IP address
    ///
    /// Queries the configured STUN servers (in order) to determine the
    /// public IP address as seen from the internet. This is useful for
    /// detecting the external IP when behind NAT.
    ///
    /// # Returns
    ///
    /// The public IP address (IPv4 or IPv6), or an error if all
    /// STUN servers fail or timeout.
    pub async fn get_public_ip(&self) -> Result<IpAddr, PublicIpError> {
        get_public_ip_stun_with_servers_and_cache(
            &self.servers,
            self.timeout,
            &self.cache,
            self.verbose,
        )
        .await
        .map_err(|e| match e {
            StunError::Timeout => PublicIpError::Timeout,
            StunError::IoError(err) => PublicIpError::HttpError(err.to_string()),
            StunError::InvalidResponse => {
                PublicIpError::ParseError("Invalid STUN response".to_string())
            }
            StunError::NoMappedAddress => {
                PublicIpError::ParseError("No mapped address in STUN response".to_string())
            }
        })
    }

    /// Get the list of configured STUN servers
    pub fn servers(&self) -> &[String] {
        &self.servers
    }

    /// Clear the STUN server address cache
    ///
    /// This removes cached DNS resolutions for STUN servers,
    /// forcing fresh DNS lookups on the next request.
    pub async fn clear_cache(&self) {
        let cache = self.cache.write().await;
        cache.clear();
    }

    /// Pre-warm the cache with STUN server addresses
    ///
    /// This method resolves and caches the IP addresses of all
    /// configured STUN servers, reducing latency for the first
    /// public IP detection.
    pub async fn prewarm_cache(&self) -> Result<(), PublicIpError> {
        let cache = self.cache.read().await;

        for server in &self.servers {
            let _ = cache.get_stun_server_addrs(server).await;
            // Ignore individual failures, as long as at least one works
        }

        Ok(())
    }

    /// Check if a STUN server address is cached
    ///
    /// # Arguments
    ///
    /// * `server` - STUN server address in "host:port" format
    ///
    /// # Returns
    ///
    /// `true` if the server's IP addresses are cached, `false` otherwise
    pub async fn is_server_cached(&self, server: &str) -> bool {
        let cache = self.cache.read().await;
        // Try to get from cache without resolving
        cache.get_stun_server_addrs(server).await.is_ok()
    }
}

impl Default for StunClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics about the STUN cache
#[derive(Debug, Clone)]
pub struct CacheStats {
    /// Number of cached server entries
    pub servers_cached: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_stun_client_default() {
        let client = StunClient::new();

        // Should have the default well-known STUN servers
        assert_eq!(client.servers().len(), STUN_SERVERS.len());
        assert!(client.servers()[0].contains("google.com"));
    }

    #[tokio::test]
    async fn test_stun_client_custom_servers() {
        let servers = vec![
            "stun.example.com:3478".to_string(),
            "stun2.example.com:3478".to_string(),
        ];

        let client = StunClient::with_servers(servers.clone());
        assert_eq!(client.servers(), &servers);
    }

    #[tokio::test]
    async fn test_stun_client_timeout() {
        let client = StunClient::new().with_timeout(Duration::from_secs(2));

        // Timeout is set internally, we can only test that the method works
        assert_eq!(client.servers().len(), STUN_SERVERS.len());
    }

    #[tokio::test]
    async fn test_custom_servers_are_queried() {
        // A client configured with only an unresolvable custom server must
        // fail: if the query path ignored the configured servers (the old
        // bug) and used the hardcoded defaults, this would succeed on any
        // machine with internet access.
        let client = StunClient::with_servers(vec!["stun.does-not-exist.invalid:3478".to_string()])
            .with_timeout(Duration::from_millis(200));

        let result = client.get_public_ip().await;
        assert!(
            result.is_err(),
            "custom unresolvable server must not fall back to default servers"
        );
    }

    #[tokio::test]
    async fn test_cache_operations() {
        let client = StunClient::new();

        // Clear cache (should not error even if empty)
        client.clear_cache().await;

        // Pre-warm cache (may fail in test environment without network)
        let _ = client.prewarm_cache().await;
    }

    #[tokio::test]
    async fn test_public_ip_detection() {
        let client = StunClient::new();

        // This test may fail in environments without internet access
        match client.get_public_ip().await {
            Ok(ip) => {
                // Should return a valid IP
                assert!(!ip.is_unspecified());
                assert!(!ip.is_loopback());
            }
            Err(_) => {
                // Network failure is acceptable in test environment
            }
        }
    }
}
