//! ASN lookup functionality using Team Cymru's whois service

use crate::asn::cache::AsnCache;
use crate::traceroute::{is_cgnat, is_internal_ip, AsnInfo};
use hickory_resolver::config::ResolverConfig;
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::TokioResolver;
use ipnet::Ipv4Net;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Error type for ASN lookup operations
#[derive(Debug, thiserror::Error)]
pub enum AsnLookupError {
    /// DNS resolution failed
    #[error("DNS resolution failed: {0}")]
    DnsError(String),

    /// Invalid response format
    #[error("Invalid ASN response format")]
    InvalidFormat,

    /// No ASN data found
    #[error("No ASN data found")]
    NotFound,
}

/// Performs ASN lookup using Team Cymru's whois service with injected cache
/// (Internal use only - users should use AsnLookup service)
pub(crate) async fn lookup_asn_with_cache(
    ipv4_addr: Ipv4Addr,
    cache: &Arc<RwLock<AsnCache>>,
    resolver: Option<Arc<TokioResolver>>,
) -> Result<AsnInfo, AsnLookupError> {
    // Check if it's a private or special IP first, before cache
    if is_internal_ip(&ipv4_addr)
        || is_cgnat(&ipv4_addr)
        || ipv4_addr.is_link_local()
        || ipv4_addr.is_broadcast()
        || ipv4_addr.is_documentation()
        || ipv4_addr.is_unspecified()
    {
        let name = if ipv4_addr.is_loopback() {
            "Loopback"
        } else if ipv4_addr.is_private() {
            "Private Network"
        } else if is_cgnat(&ipv4_addr) {
            "Carrier Grade NAT"
        } else {
            "Special Use"
        }
        .to_string();

        let asn_info = AsnInfo {
            asn: 0, // 0 indicates N/A for private/special IPs
            prefix: ipv4_addr.to_string() + "/32",
            country_code: "N/A".to_string(),
            registry: "N/A".to_string(),
            name,
        };

        // Cache the result
        if let Ok(net) = asn_info.prefix.parse::<Ipv4Net>() {
            let cache_write = cache.write().await;
            cache_write.insert(net, asn_info.clone());
        }

        return Ok(asn_info);
    }

    // Check cache for non-special IPs
    {
        let cache_read = cache.read().await;
        if let Some(cached) = cache_read.get(&ipv4_addr) {
            return Ok(cached);
        }
    }

    // Use provided resolver or create a new one
    let resolver = match resolver {
        Some(r) => r,
        None => Arc::new(
            TokioResolver::builder_with_config(
                ResolverConfig::cloudflare(),
                TokioConnectionProvider::default(),
            )
            .build(),
        ),
    };

    // Query Team Cymru DNS
    let octets = ipv4_addr.octets();
    let query = format!(
        "{}.{}.{}.{}.origin.asn.cymru.com",
        octets[3], octets[2], octets[1], octets[0]
    );

    let lookup = resolver
        .txt_lookup(query)
        .await
        .map_err(|e| AsnLookupError::DnsError(e.to_string()))?;

    let record = lookup.iter().next().ok_or(AsnLookupError::NotFound)?;

    let txt_data = record
        .iter()
        .map(|data| String::from_utf8_lossy(data))
        .collect::<Vec<_>>()
        .join("");

    let parts: Vec<&str> = txt_data.split('|').map(str::trim).collect();
    if parts.len() < 3 {
        return Err(AsnLookupError::InvalidFormat);
    }

    // Parse ASN as u32, handling potential "AS" prefix
    let asn_str = parts[0].trim_start_matches("AS");
    let asn = asn_str.parse::<u32>().unwrap_or(0);
    let prefix = parts[1].to_string();
    let country_code = parts[2].to_string();
    let registry = if parts.len() > 3 {
        parts[3].to_string()
    } else {
        String::new()
    };

    // Parse prefix to create Ipv4Net
    let net = prefix
        .parse::<Ipv4Net>()
        .map_err(|_| AsnLookupError::InvalidFormat)?;

    // Query for AS name
    let as_query = format!("AS{asn}.asn.cymru.com");
    let name = match resolver.txt_lookup(as_query).await {
        Ok(as_lookup) => {
            if let Some(as_record) = as_lookup.iter().next() {
                let as_txt = as_record
                    .iter()
                    .map(|data| String::from_utf8_lossy(data))
                    .collect::<Vec<_>>()
                    .join("");
                let as_parts: Vec<&str> = as_txt.split('|').map(str::trim).collect();
                if as_parts.len() >= 5 {
                    // Format is: ASN | CC | Registry | Allocated | AS Name
                    let mut as_name = as_parts[4].to_string();
                    // Team Cymru often includes ", CC" at the end of the name - remove it
                    if as_name.ends_with(&format!(", {}", country_code)) {
                        as_name.truncate(as_name.len() - country_code.len() - 2);
                    }
                    as_name
                } else if as_parts.len() >= 2 {
                    as_parts[1].to_string()
                } else {
                    String::new()
                }
            } else {
                String::new()
            }
        }
        Err(_) => String::new(),
    };

    let asn_info = AsnInfo {
        asn,
        prefix: prefix.clone(),
        country_code,
        registry,
        name,
    };

    // Cache the result
    let cache_write = cache.write().await;
    cache_write.insert(net, asn_info.clone());

    Ok(asn_info)
}

/// Create a default DNS resolver for ASN lookups
pub fn create_default_resolver() -> Arc<TokioResolver> {
    Arc::new(
        TokioResolver::builder_with_config(
            ResolverConfig::cloudflare(),
            TokioConnectionProvider::default(),
        )
        .build(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::create_default_resolver;

    #[tokio::test]
    async fn test_lookup_private_ip() {
        let cache = Arc::new(RwLock::new(crate::asn::cache::AsnCache::new()));
        let ip: Ipv4Addr = "192.168.1.1".parse().unwrap();
        let result = lookup_asn_with_cache(ip, &cache, None).await;
        assert!(result.is_ok());
        let asn_info = result.unwrap();
        assert_eq!(asn_info.asn, 0);
        assert_eq!(asn_info.name, "Private Network");
    }

    #[tokio::test]
    async fn test_lookup_cgnat_ip() {
        let cache = Arc::new(RwLock::new(crate::asn::cache::AsnCache::new()));
        let ip: Ipv4Addr = "100.64.0.1".parse().unwrap();
        let result = lookup_asn_with_cache(ip, &cache, None).await;
        match &result {
            Ok(asn_info) => {
                assert_eq!(asn_info.asn, 0);
                assert_eq!(asn_info.name, "Carrier Grade NAT");
            }
            Err(e) => panic!("Expected Ok, got error: {:?}", e),
        }
    }

    #[tokio::test]
    async fn test_lookup_loopback() {
        let cache = Arc::new(RwLock::new(crate::asn::cache::AsnCache::new()));
        let ip: Ipv4Addr = "127.0.0.1".parse().unwrap();
        let result = lookup_asn_with_cache(ip, &cache, None).await;
        assert!(result.is_ok());
        let asn_info = result.unwrap();
        assert_eq!(asn_info.asn, 0);
        assert_eq!(asn_info.name, "Loopback");
    }

    #[tokio::test]
    async fn test_cache_usage() {
        // Create isolated cache for test
        let cache = Arc::new(RwLock::new(crate::asn::cache::AsnCache::new()));

        let ip: Ipv4Addr = "10.0.0.1".parse().unwrap();

        // First lookup - should populate cache
        let result1 = lookup_asn_with_cache(ip, &cache, None).await;
        assert!(result1.is_ok());

        // Second lookup - should use cache
        let result2 = lookup_asn_with_cache(ip, &cache, None).await;
        assert!(result2.is_ok());
        assert_eq!(result1.unwrap().name, result2.unwrap().name);
    }

    #[tokio::test]
    async fn test_special_ips() {
        let cache = Arc::new(RwLock::new(crate::asn::cache::AsnCache::new()));
        // Test various special IP addresses
        let test_cases = vec![
            ("0.0.0.0", "Special Use"),         // Unspecified
            ("169.254.1.1", "Special Use"),     // Link-local
            ("255.255.255.255", "Special Use"), // Broadcast
            ("198.51.100.1", "Special Use"),    // Documentation
        ];

        for (ip_str, expected_name) in test_cases {
            let ip: Ipv4Addr = ip_str.parse().unwrap();
            let result = lookup_asn_with_cache(ip, &cache, None).await;
            assert!(result.is_ok(), "Failed for IP: {}", ip_str);
            let asn_info = result.unwrap();
            assert_eq!(asn_info.asn, 0);
            assert_eq!(
                asn_info.name, expected_name,
                "Wrong name for IP: {}",
                ip_str
            );
        }
    }

    #[tokio::test]
    async fn test_lookup_public_ip() {
        let cache = Arc::new(RwLock::new(crate::asn::cache::AsnCache::new()));
        // Test with known public IPs and their expected ASNs
        let test_cases = vec![
            ("8.8.8.8", "15169", "GOOGLE"),                // Google DNS
            ("1.1.1.1", "13335", "CLOUDFLARENET"),         // Cloudflare DNS
            ("208.67.222.222", "36692", "CISCO-UMBRELLA"), // OpenDNS (now Cisco Umbrella)
        ];

        for (ip_str, expected_asn, expected_name_prefix) in test_cases {
            let ip: Ipv4Addr = ip_str.parse().unwrap();
            let result = lookup_asn_with_cache(ip, &cache, None).await;

            assert!(
                result.is_ok(),
                "ASN lookup failed for {}: {:?}",
                ip_str,
                result.err()
            );
            let asn_info = result.unwrap();

            // Verify ASN matches expected
            let expected_asn_num: u32 = expected_asn.parse().expect("Invalid ASN in test");
            assert_eq!(
                asn_info.asn, expected_asn_num,
                "Wrong ASN for {}: expected {}, got {}",
                ip_str, expected_asn_num, asn_info.asn
            );

            // Verify name contains expected prefix
            assert!(
                asn_info.name.contains(expected_name_prefix),
                "ASN name for {} doesn't contain '{}': got '{}'",
                ip_str,
                expected_name_prefix,
                asn_info.name
            );

            // Basic validation
            assert!(!asn_info.prefix.is_empty(), "Empty prefix for {}", ip_str);
            assert!(
                !asn_info.country_code.is_empty(),
                "Empty country code for {}",
                ip_str
            );

            eprintln!(
                "✓ IP {} -> ASN: {}, Name: '{}', Country: '{}'",
                ip_str, asn_info.asn, asn_info.name, asn_info.country_code
            );
        }
    }

    #[tokio::test]
    async fn test_custom_resolver() {
        let cache = Arc::new(RwLock::new(crate::asn::cache::AsnCache::new()));
        let resolver = Arc::new(create_default_resolver());
        let ip: Ipv4Addr = "192.168.1.1".parse().unwrap();
        let result = lookup_asn_with_cache(ip, &cache, Some(resolver)).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_cache_multiple_ips_same_prefix() {
        // Create isolated cache for test
        let cache = Arc::new(RwLock::new(crate::asn::cache::AsnCache::new()));

        // Two IPs in the same private network
        let ip1: Ipv4Addr = "192.168.1.1".parse().unwrap();
        let ip2: Ipv4Addr = "192.168.1.2".parse().unwrap();

        // First lookup
        let result1 = lookup_asn_with_cache(ip1, &cache, None).await;
        assert!(result1.is_ok());

        // Second lookup - different IP but should still benefit from cache
        // if the cache is using prefix-based lookups
        let result2 = lookup_asn_with_cache(ip2, &cache, None).await;
        assert!(result2.is_ok());

        // Both should be private network
        assert_eq!(result1.unwrap().name, "Private Network");
        assert_eq!(result2.unwrap().name, "Private Network");
    }

    #[test]
    fn test_error_display() {
        let errors = vec![
            AsnLookupError::DnsError("timeout".to_string()),
            AsnLookupError::InvalidFormat,
            AsnLookupError::NotFound,
        ];

        for error in errors {
            let error_str = error.to_string();
            assert!(!error_str.is_empty());

            match error {
                AsnLookupError::DnsError(msg) => assert!(error_str.contains(&msg)),
                AsnLookupError::InvalidFormat => assert!(error_str.contains("Invalid")),
                AsnLookupError::NotFound => assert!(error_str.contains("No ASN")),
            }
        }
    }

    #[tokio::test]
    async fn test_concurrent_lookups() {
        use tokio::task::JoinSet;

        let ips = vec![
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(172, 16, 0, 1),
            Ipv4Addr::new(127, 0, 0, 1),
        ];

        let mut tasks = JoinSet::new();

        for ip in ips {
            let cache = Arc::new(RwLock::new(crate::asn::cache::AsnCache::new()));
            tasks.spawn(async move { lookup_asn_with_cache(ip, &cache, None).await });
        }

        let mut results = Vec::new();
        while let Some(result) = tasks.join_next().await {
            match result {
                Ok(asn_result) => results.push(asn_result),
                Err(e) => eprintln!("Task failed: {}", e),
            }
        }

        // All should succeed since they're all special IPs
        assert_eq!(results.len(), 4);
        for result in results {
            assert!(result.is_ok());
        }
    }
}
