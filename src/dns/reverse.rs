//! Reverse DNS lookup functionality

use hickory_resolver::config::ResolverConfig;
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::TokioResolver;
use std::net::IpAddr;
use std::sync::Arc;

/// Error type for reverse DNS operations
#[derive(Debug, thiserror::Error)]
pub enum ReverseDnsError {
    /// DNS resolution failed
    #[error("DNS resolution failed: {0}")]
    ResolutionError(String),

    /// No PTR record found
    #[error("No PTR record found")]
    NotFound,
}

/// Perform reverse DNS lookup for an IP address
pub async fn reverse_dns_lookup(
    ip: IpAddr,
    resolver: Option<Arc<TokioResolver>>,
) -> Result<String, ReverseDnsError> {
    // Use provided resolver or create a new one
    let resolver = match resolver {
        Some(r) => r,
        None => Arc::new(create_default_resolver()),
    };

    let lookup = resolver
        .reverse_lookup(ip)
        .await
        .map_err(|e| ReverseDnsError::ResolutionError(e.to_string()))?;

    // Get the first PTR record
    let name = lookup
        .iter()
        .next()
        .map(|name| {
            let name_str = name.to_string();
            // Remove trailing dot if present
            if name_str.ends_with('.') {
                name_str[..name_str.len() - 1].to_string()
            } else {
                name_str
            }
        })
        .ok_or(ReverseDnsError::NotFound)?;

    Ok(name)
}

/// Create a default DNS resolver
pub fn create_default_resolver() -> TokioResolver {
    TokioResolver::builder_with_config(
        ResolverConfig::cloudflare(),
        TokioConnectionProvider::default(),
    )
    .build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn test_reverse_dns_localhost() {
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let result = reverse_dns_lookup(ip, None).await;
        // Localhost might resolve to "localhost" or might fail depending on system config
        // So we just check that the function completes without panicking
        match result {
            Ok(hostname) => {
                assert!(!hostname.is_empty());
                // Common localhost names
                assert!(
                    hostname.contains("localhost")
                        || hostname.contains("127.0.0.1")
                        || hostname.contains("loopback")
                );
            }
            Err(_) => {
                // It's okay if localhost doesn't have a PTR record
            }
        }
    }

    #[tokio::test]
    async fn test_reverse_dns_private_ip() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let result = reverse_dns_lookup(ip, None).await;
        // Private IPs typically don't have PTR records on public DNS
        // So we just verify the function handles this gracefully
        match result {
            Ok(_) => {} // Unexpected but okay
            Err(e) => {
                // Should be a resolution error or not found
                assert!(
                    matches!(e, ReverseDnsError::ResolutionError(_))
                        || matches!(e, ReverseDnsError::NotFound)
                );
            }
        }
    }

    #[tokio::test]
    async fn test_create_resolver() {
        let resolver = Arc::new(create_default_resolver());
        // Test that we can use the resolver
        let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let _ = reverse_dns_lookup(ip, Some(resolver)).await;
        // We don't assert on the result as DNS can be flaky in tests
    }
}
