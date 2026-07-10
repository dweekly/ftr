//! Async enrichment service
//!
//! This module provides parallel DNS and ASN lookups for discovered IP addresses.

use crate::services::Services;
use crate::traceroute::AsnInfo;
use crate::traceroute::TracerouteError;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::task::JoinSet;

/// Enrichment result for an IP address
#[derive(Debug, Clone)]
pub struct EnrichmentResult {
    /// The IP address that was enriched
    pub addr: IpAddr,
    /// The reverse DNS hostname, if found
    pub hostname: Option<String>,
    /// ASN information for the IP address
    pub asn_info: Option<AsnInfo>,
}

/// Async enrichment service
pub struct EnrichmentService {
    services: Arc<Services>,
}

impl EnrichmentService {
    /// Create a new async enrichment service with fresh default services
    pub async fn new() -> Result<Self, TracerouteError> {
        Self::new_with_services(Arc::new(Services::new())).await
    }

    /// Create a new async enrichment service backed by the provided services
    ///
    /// All DNS and ASN lookups performed during enrichment go through
    /// `services`, so any caches owned by those services (e.g. pre-warmed
    /// via [`crate::Ftr::with_caches`]) are honored.
    pub async fn new_with_services(services: Arc<Services>) -> Result<Self, TracerouteError> {
        Ok(Self { services })
    }

    /// Enrich a set of IP addresses and wait for results
    pub async fn enrich_addresses(
        &self,
        addresses: Vec<IpAddr>,
    ) -> HashMap<IpAddr, EnrichmentResult> {
        let mut enrichment_futures = JoinSet::new();

        for addr in addresses {
            let services = Arc::clone(&self.services);

            enrichment_futures.spawn(async move {
                let dns_future = services.rdns.lookup(addr);
                let asn_future = services.asn.lookup(addr);

                let (hostname_result, asn_result) = tokio::join!(dns_future, asn_future);

                let hostname = hostname_result.ok();
                let asn_info = asn_result.ok();

                EnrichmentResult {
                    addr,
                    hostname,
                    asn_info,
                }
            });
        }

        let mut results = HashMap::new();
        while let Some(Ok(result)) = enrichment_futures.join_next().await {
            results.insert(result.addr, result);
        }

        results
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[tokio::test]
    async fn test_enrichment_service_creation() {
        let service = EnrichmentService::new().await;
        assert!(service.is_ok());
    }

    #[tokio::test]
    async fn test_enrich_addresses() {
        let service = EnrichmentService::new()
            .await
            .expect("enrichment service creation should succeed");
        let addresses = vec![
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        ];

        // 30s timeout: network tests run ~10x slower under coverage instrumentation
        let results = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            service.enrich_addresses(addresses.clone()),
        )
        .await
        .expect("Enrichment timed out");

        // Should have results for all addresses
        assert_eq!(results.len(), addresses.len());

        // Check that all requested addresses have results
        for addr in &addresses {
            assert!(results.contains_key(addr));
            let result = &results[addr];
            assert_eq!(result.addr, *addr);
        }

        // Localhost PTR resolution is system-dependent
        let localhost_result = &results[&IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))];
        // hostname may or may not resolve depending on DNS config
        let _ = localhost_result.hostname.as_ref();

        // Public IPs should have ASN info
        let google_dns = &results[&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))];
        assert!(google_dns.asn_info.is_some());
    }

    #[tokio::test]
    async fn test_enrichment_result_fields() {
        let addr = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let result = EnrichmentResult {
            addr,
            hostname: Some("dns.google".to_string()),
            asn_info: Some(AsnInfo {
                asn: 15169,
                name: "GOOGLE".to_string(),
                prefix: "8.8.8.0/24".to_string(),
                country_code: "US".to_string(),
                registry: "arin".to_string(),
            }),
        };

        assert_eq!(result.addr, addr);
        assert_eq!(result.hostname, Some("dns.google".to_string()));
        assert!(result.asn_info.is_some());

        let asn = result.asn_info.expect("asn_info should be set");
        assert_eq!(asn.asn, 15169);
        assert_eq!(asn.name, "GOOGLE");
    }

    #[tokio::test]
    async fn test_ipv6_enrichment() {
        let service = EnrichmentService::new()
            .await
            .expect("enrichment service creation should succeed");
        let ipv6_addr: IpAddr = "2001:4860:4860::8888".parse().expect("valid IPv6 address");

        let results = service.enrich_addresses(vec![ipv6_addr]).await;

        assert!(results.contains_key(&ipv6_addr));
        let result = &results[&ipv6_addr];

        // IPv6 ASN lookups aren't supported yet, so asn_info should be None
        assert!(result.asn_info.is_none());

        // But DNS lookup should work
        assert_eq!(result.addr, ipv6_addr);
    }

    #[tokio::test]
    async fn test_enrichment_uses_injected_services() {
        use crate::asn::cache::AsnCache;
        use crate::dns::cache::RdnsCache;

        let addr: IpAddr = "8.8.8.8".parse().expect("valid IP");

        // Pre-warm caches with sentinel values. Cache hits are served before
        // any network I/O, so this test is deterministic and offline-safe:
        // if the injected services were ignored (the old bug), enrichment
        // would perform live lookups and never return these sentinels.
        let asn_cache = AsnCache::new();
        asn_cache.insert(
            "8.8.8.0/24".parse().expect("valid prefix"),
            AsnInfo {
                asn: 64512,
                name: "SENTINEL-AS".to_string(),
                prefix: "8.8.8.0/24".to_string(),
                country_code: "ZZ".to_string(),
                registry: "test".to_string(),
            },
        );
        let rdns_cache = RdnsCache::with_default_ttl();
        rdns_cache.insert(addr, "sentinel.rdns.test".to_string());

        let services = Arc::new(Services::with_caches(
            Some(asn_cache),
            Some(rdns_cache),
            None,
        ));
        let service = EnrichmentService::new_with_services(services)
            .await
            .expect("service creation");

        let results = service.enrich_addresses(vec![addr]).await;
        let result = results.get(&addr).expect("result for address");

        assert_eq!(result.hostname.as_deref(), Some("sentinel.rdns.test"));
        let asn = result.asn_info.as_ref().expect("ASN info from cache");
        assert_eq!(asn.asn, 64512);
        assert_eq!(asn.name, "SENTINEL-AS");
    }

    #[tokio::test]
    async fn test_private_ip_enrichment() {
        let service = EnrichmentService::new()
            .await
            .expect("enrichment service creation should succeed");
        let private_addrs = vec![
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)),
        ];

        let results = service.enrich_addresses(private_addrs.clone()).await;

        // Should have results for all addresses
        assert_eq!(results.len(), private_addrs.len());

        // Private IPs should have ASN info with asn: 0
        for addr in &private_addrs {
            let result = &results[addr];
            assert!(result.asn_info.is_some());
            let asn_info = result
                .asn_info
                .as_ref()
                .expect("private IP should have ASN info");
            assert_eq!(asn_info.asn, 0); // Private IPs get ASN 0
            assert_eq!(asn_info.name, "Private Network");
        }
    }
}
