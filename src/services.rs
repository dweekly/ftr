//! Service container for the Ftr library
//!
//! This module provides a unified container for all services used
//! throughout the library, offering a service-oriented API that
//! focuses on what services do rather than how they're implemented.

use crate::asn::service::AsnLookup;
use crate::dns::service::RdnsLookup;
use crate::public_ip::service::StunClient;
use std::sync::Arc;

/// Container for all services used by the Ftr library
///
/// This struct provides access to the various network services
/// (ASN lookup, reverse DNS, STUN) through a clean, service-oriented API.
/// Services are already thread-safe internally, so no outer locking is needed.
///
/// # Examples
///
/// ```no_run
/// use ftr::services::Services;
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let services = Services::new();
///     
///     // Services can be used directly without locking
///     let asn_info = services.asn.lookup("8.8.8.8".parse()?).await?;
///     
///     Ok(())
/// }
/// ```
#[derive(Clone, Debug)]
pub struct Services {
    /// ASN lookup service
    pub asn: Arc<AsnLookup>,
    /// Reverse DNS lookup service
    pub rdns: Arc<RdnsLookup>,
    /// STUN client for public IP detection
    pub stun: Arc<StunClient>,
}

impl Services {
    /// Create a new set of services with default configuration
    pub fn new() -> Self {
        Self {
            asn: Arc::new(AsnLookup::new()),
            rdns: Arc::new(RdnsLookup::new()),
            stun: Arc::new(StunClient::new()),
        }
    }

    /// Create services with optional custom implementations
    ///
    /// Any service not provided will be created with default configuration.
    ///
    /// # Arguments
    ///
    /// * `asn` - Optional custom ASN lookup service
    /// * `rdns` - Optional custom reverse DNS lookup service
    /// * `stun` - Optional custom STUN client
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use ftr::services::Services;
    /// use ftr::asn::service::AsnLookup;
    /// use ftr::dns::service::RdnsLookup;
    /// use std::time::Duration;
    ///
    /// // Create services with custom configuration
    /// let asn = AsnLookup::new();
    /// let rdns = RdnsLookup::with_ttl(Duration::from_secs(300));
    /// let services = Services::with_services(Some(asn), Some(rdns), None);
    /// ```
    pub fn with_services(
        asn: Option<AsnLookup>,
        rdns: Option<RdnsLookup>,
        stun: Option<StunClient>,
    ) -> Self {
        Self {
            asn: Arc::new(asn.unwrap_or_default()),
            rdns: Arc::new(rdns.unwrap_or_default()),
            stun: Arc::new(stun.unwrap_or_default()),
        }
    }

    /// Create services with optional pre-initialized caches
    ///
    /// This method creates services using the provided caches.
    /// Any cache not provided will be created fresh.
    ///
    /// # Arguments
    ///
    /// * `asn_cache` - Optional pre-populated ASN cache
    /// * `rdns_cache` - Optional pre-populated reverse DNS cache
    /// * `stun_cache` - Optional pre-populated STUN cache
    pub fn with_caches(
        asn_cache: Option<crate::asn::cache::AsnCache>,
        rdns_cache: Option<crate::dns::cache::RdnsCache>,
        stun_cache: Option<crate::public_ip::stun_cache::StunCache>,
    ) -> Self {
        let asn = if let Some(cache) = asn_cache {
            AsnLookup::with_cache(cache, None)
        } else {
            AsnLookup::new()
        };

        let rdns = if let Some(cache) = rdns_cache {
            RdnsLookup::with_cache(cache, None)
        } else {
            RdnsLookup::new()
        };

        let stun = if let Some(cache) = stun_cache {
            StunClient::with_cache(
                cache,
                vec![
                    "stun.l.google.com:19302".to_string(),
                    "stun1.l.google.com:19302".to_string(),
                ],
            )
        } else {
            StunClient::new()
        };

        Self {
            asn: Arc::new(asn),
            rdns: Arc::new(rdns),
            stun: Arc::new(stun),
        }
    }

    /// Clear all caches across all services
    ///
    /// This is useful for testing or when you want to force
    /// fresh lookups for all subsequent queries.
    pub async fn clear_all_caches(&self) {
        self.asn.clear_cache().await;
        self.rdns.clear_cache().await;
        self.stun.clear_cache().await;
    }
}

impl Default for Services {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_services_creation() {
        let services = Services::new();

        // Services should be directly accessible without locking
        // Test that we can call methods on them
        let ip: std::net::IpAddr = "192.168.1.1".parse().unwrap();
        let _ = services.asn.lookup(ip).await;

        // Should be able to clear all caches
        services.clear_all_caches().await;
    }

    #[tokio::test]
    async fn test_services_with_custom() {
        use std::time::Duration;

        let custom_rdns = RdnsLookup::with_ttl(Duration::from_secs(120));
        let services = Services::with_services(None, Some(custom_rdns), None);

        // Should have the custom rdns service and be able to use it
        let ip: std::net::IpAddr = "8.8.8.8".parse().unwrap();
        let _ = services.rdns.lookup(ip).await;
    }

    #[tokio::test]
    async fn test_services_clone() {
        let services1 = Services::new();
        let services2 = services1.clone();

        // Both should reference the same underlying services
        // (Arc ensures they share the same instances)
        // Test by verifying both can be used
        let ip: std::net::IpAddr = "10.0.0.1".parse().unwrap();
        let _ = services1.asn.lookup(ip).await;
        let _ = services2.asn.lookup(ip).await;
    }
}
