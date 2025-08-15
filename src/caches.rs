//! Centralized cache management for the Ftr library
//!
//! This module provides a unified cache structure that owns all the
//! various caches used throughout the library (ASN, DNS, STUN).

use std::sync::Arc;
use tokio::sync::RwLock;

/// Container for all caches used by the Ftr library
#[derive(Clone, Debug)]
pub struct Caches {
    /// ASN lookup cache
    pub asn: Arc<RwLock<crate::asn::cache::AsnCache>>,
    /// Reverse DNS lookup cache
    pub rdns: Arc<RwLock<crate::dns::cache::RdnsCache>>,
    /// STUN server cache for public IP detection
    pub stun: Arc<RwLock<crate::public_ip::stun_cache::StunCache>>,
}

impl Caches {
    /// Create a new set of caches with optional pre-initialized caches
    ///
    /// Any cache not provided will be created fresh.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use ftr::caches::Caches;
    /// use ftr::asn::cache::AsnCache;
    /// use ftr::dns::cache::RdnsCache;
    /// use ftr::public_ip::stun_cache::StunCache;
    ///
    /// // All new caches
    /// let caches = Caches::new(None, None, None);
    ///
    /// // With a pre-warmed ASN cache
    /// let asn_cache = AsnCache::new();
    /// // ... pre-populate asn_cache ...
    /// let caches = Caches::new(Some(asn_cache), None, None);
    ///
    /// // With multiple pre-initialized caches
    /// let asn_cache2 = AsnCache::new();
    /// let rdns_cache = RdnsCache::with_default_ttl();
    /// let caches = Caches::new(Some(asn_cache2), Some(rdns_cache), None);
    /// ```
    pub fn new(
        asn_cache: Option<crate::asn::cache::AsnCache>,
        rdns_cache: Option<crate::dns::cache::RdnsCache>,
        stun_cache: Option<crate::public_ip::stun_cache::StunCache>,
    ) -> Self {
        Self {
            asn: Arc::new(RwLock::new(asn_cache.unwrap_or_default())),
            rdns: Arc::new(RwLock::new(
                rdns_cache.unwrap_or_else(crate::dns::cache::RdnsCache::with_default_ttl),
            )),
            stun: Arc::new(RwLock::new(stun_cache.unwrap_or_default())),
        }
    }
}

impl Default for Caches {
    fn default() -> Self {
        Self::new(None, None, None)
    }
}
