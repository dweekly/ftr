//! Async enrichment service
//!
//! This module provides parallel DNS and ASN lookups for discovered IP addresses.

use crate::services::Services;
use crate::traceroute::AsnInfo;
use anyhow::Result;
use futures::stream::{FuturesUnordered, StreamExt};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};

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
pub struct AsyncEnrichmentService {
    services: Arc<Services>,
    seen_addresses: Arc<RwLock<HashSet<IpAddr>>>,
    enrichment_tx: mpsc::UnboundedSender<IpAddr>,
    enrichment_rx: Arc<RwLock<mpsc::UnboundedReceiver<IpAddr>>>,
}

impl AsyncEnrichmentService {
    /// Create a new async enrichment service
    pub async fn new() -> Result<Self> {
        let services = Arc::new(Services::new());
        let (enrichment_tx, enrichment_rx) = mpsc::unbounded_channel();

        Ok(Self {
            services,
            seen_addresses: Arc::new(RwLock::new(HashSet::new())),
            enrichment_tx,
            enrichment_rx: Arc::new(RwLock::new(enrichment_rx)),
        })
    }

    /// Enqueue an IP address for enrichment
    pub async fn enqueue(&self, addr: IpAddr) -> Result<()> {
        let mut seen = self.seen_addresses.write().await;
        if seen.insert(addr) {
            self.enrichment_tx.send(addr)?;
        }
        Ok(())
    }

    /// Start background enrichment processing
    pub async fn start_background_enrichment(self: Arc<Self>) -> HashMap<IpAddr, EnrichmentResult> {
        let mut results = HashMap::new();
        let mut enrichment_futures = FuturesUnordered::new();

        // Take ownership of the receiver
        let mut rx = self.enrichment_rx.write().await;

        // Process enrichment queue
        loop {
            tokio::select! {
                // Check for new addresses to enrich
                Some(addr) = rx.recv() => {
                    let services = Arc::clone(&self.services);

                    // Spawn parallel DNS and ASN lookups
                    let enrichment_future = async move {
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
                    };

                    enrichment_futures.push(enrichment_future);
                }

                // Collect completed enrichments
                Some(result) = enrichment_futures.next() => {
                    results.insert(result.addr, result);
                }

                // Exit when queue is empty and all futures are done
                else => {
                    if enrichment_futures.is_empty() {
                        break;
                    }
                }
            }
        }

        results
    }

    /// Enrich a set of IP addresses and wait for results
    pub async fn enrich_addresses(
        &self,
        addresses: Vec<IpAddr>,
    ) -> HashMap<IpAddr, EnrichmentResult> {
        let mut enrichment_futures = FuturesUnordered::new();

        for addr in addresses {
            let services = Arc::clone(&self.services);

            let enrichment_future = async move {
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
            };

            enrichment_futures.push(enrichment_future);
        }

        let mut results = HashMap::new();
        while let Some(result) = enrichment_futures.next().await {
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
        let service = AsyncEnrichmentService::new().await;
        assert!(service.is_ok());
    }

    #[tokio::test]
    async fn test_enqueue_deduplication() {
        let service = Arc::new(AsyncEnrichmentService::new().await.unwrap());
        let addr: IpAddr = "8.8.8.8".parse().unwrap();

        // First enqueue should succeed
        assert!(service.enqueue(addr).await.is_ok());

        // Second enqueue of same address should be deduplicated
        assert!(service.enqueue(addr).await.is_ok());

        // Check that only one address is in seen set
        let seen = service.seen_addresses.read().await;
        assert_eq!(seen.len(), 1);
        assert!(seen.contains(&addr));
    }

    #[tokio::test]
    async fn test_enrich_addresses() {
        let service = AsyncEnrichmentService::new().await.unwrap();
        let addresses = vec![
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        ];

        // Add timeout to prevent hanging on network issues
        let results = tokio::time::timeout(
            std::time::Duration::from_secs(10),
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

        // Localhost should have a hostname
        let localhost_result = &results[&IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))];
        assert!(localhost_result.hostname.is_some());

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

        let asn = result.asn_info.unwrap();
        assert_eq!(asn.asn, 15169);
        assert_eq!(asn.name, "GOOGLE");
    }

    #[tokio::test]
    async fn test_background_enrichment() {
        // Create service without Arc first
        let mut service = AsyncEnrichmentService::new().await.unwrap();
        let addr1: IpAddr = "8.8.8.8".parse().unwrap();
        let addr2: IpAddr = "1.1.1.1".parse().unwrap();

        // Enqueue addresses
        service.enqueue(addr1).await.unwrap();
        service.enqueue(addr2).await.unwrap();

        // Take the sender out to close it
        let tx = std::mem::replace(&mut service.enrichment_tx, mpsc::unbounded_channel().0);
        drop(tx); // This actually closes the channel

        // Now wrap in Arc for background processing
        let service = Arc::new(service);

        // Start background enrichment with timeout to prevent hanging
        let results = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            service.start_background_enrichment(),
        )
        .await
        .expect("Background enrichment timed out");

        // Should have results for both addresses
        assert!(results.contains_key(&addr1));
        assert!(results.contains_key(&addr2));
    }

    #[tokio::test]
    async fn test_ipv6_enrichment() {
        let service = AsyncEnrichmentService::new().await.unwrap();
        let ipv6_addr: IpAddr = "2001:4860:4860::8888".parse().unwrap();

        let results = service.enrich_addresses(vec![ipv6_addr]).await;

        assert!(results.contains_key(&ipv6_addr));
        let result = &results[&ipv6_addr];

        // IPv6 ASN lookups aren't supported yet, so asn_info should be None
        assert!(result.asn_info.is_none());

        // But DNS lookup should work
        assert_eq!(result.addr, ipv6_addr);
    }

    #[tokio::test]
    async fn test_private_ip_enrichment() {
        let service = AsyncEnrichmentService::new().await.unwrap();
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
            let asn_info = result.asn_info.as_ref().unwrap();
            assert_eq!(asn_info.asn, 0); // Private IPs get ASN 0
            assert_eq!(asn_info.name, "Private Network");
        }
    }
}
