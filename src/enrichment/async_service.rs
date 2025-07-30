//! Async enrichment service
//!
//! This module provides parallel DNS and ASN lookups for discovered IP addresses.

use crate::asn::cache::AsnCache;
use crate::traceroute::AsnInfo;
use anyhow::Result;
use futures::stream::{FuturesUnordered, StreamExt};
use hickory_resolver::config::ResolverConfig;
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::TokioResolver;
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
    dns_resolver: Arc<TokioResolver>,
    asn_cache: Arc<AsnCache>,
    seen_addresses: Arc<RwLock<HashSet<IpAddr>>>,
    enrichment_tx: mpsc::UnboundedSender<IpAddr>,
    enrichment_rx: Arc<RwLock<mpsc::UnboundedReceiver<IpAddr>>>,
}

impl AsyncEnrichmentService {
    /// Create a new async enrichment service
    pub async fn new() -> Result<Self> {
        let dns_resolver = TokioResolver::builder_with_config(
            ResolverConfig::cloudflare(),
            TokioConnectionProvider::default(),
        )
        .build();
        let asn_cache = AsnCache::new();
        let (enrichment_tx, enrichment_rx) = mpsc::unbounded_channel();

        Ok(Self {
            dns_resolver: Arc::new(dns_resolver),
            asn_cache: Arc::new(asn_cache),
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
                    let dns_resolver = Arc::clone(&self.dns_resolver);
                    let asn_cache = Arc::clone(&self.asn_cache);
                    
                    // Spawn parallel DNS and ASN lookups
                    let enrichment_future = async move {
                        let dns_future = lookup_dns(dns_resolver, addr);
                        let asn_future = lookup_asn(asn_cache, addr);
                        
                        let (hostname, asn_info) = tokio::join!(dns_future, asn_future);
                        
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
    pub async fn enrich_addresses(&self, addresses: Vec<IpAddr>) -> HashMap<IpAddr, EnrichmentResult> {
        let mut enrichment_futures = FuturesUnordered::new();
        
        for addr in addresses {
            let dns_resolver = Arc::clone(&self.dns_resolver);
            let asn_cache = Arc::clone(&self.asn_cache);
            
            let enrichment_future = async move {
                let dns_future = lookup_dns(dns_resolver, addr);
                let asn_future = lookup_asn(asn_cache, addr);
                
                let (hostname, asn_info) = tokio::join!(dns_future, asn_future);
                
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

/// Perform DNS reverse lookup
async fn lookup_dns(resolver: Arc<TokioResolver>, addr: IpAddr) -> Option<String> {
    match resolver.reverse_lookup(addr).await {
        Ok(response) => response
            .iter()
            .next()
            .map(|name| name.to_string().trim_end_matches('.').to_string()),
        Err(_) => None,
    }
}

/// Perform ASN lookup
async fn lookup_asn(asn_cache: Arc<AsnCache>, addr: IpAddr) -> Option<AsnInfo> {
    if let IpAddr::V4(ipv4) = addr {
        // First check cache
        if let Some(asn_info) = asn_cache.get(&ipv4) {
            return Some(asn_info);
        }
        
        // If not in cache, perform lookup
        if let Ok(asn_info) = crate::asn::lookup::lookup_asn(ipv4, None).await {
            // Cache the result
            if let Ok(prefix) = asn_info.prefix.parse() {
                asn_cache.insert(prefix, asn_info.clone());
            }
            Some(asn_info)
        } else {
            None
        }
    } else {
        None
    }
}