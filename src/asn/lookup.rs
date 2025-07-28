//! ASN lookup functionality using Team Cymru's whois service

use crate::asn::cache::ASN_CACHE;
use crate::traceroute::{is_cgnat, is_internal_ip, AsnInfo};
use hickory_resolver::config::ResolverConfig;
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::TokioResolver;
use ipnet::Ipv4Net;
use std::net::Ipv4Addr;
use std::sync::Arc;

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

/// Performs ASN lookup using Team Cymru's whois service
pub async fn lookup_asn(
    ipv4_addr: Ipv4Addr,
    resolver: Option<Arc<TokioResolver>>,
) -> Result<AsnInfo, AsnLookupError> {
    // Check cache first
    if let Some(cached) = ASN_CACHE.get(&ipv4_addr) {
        return Ok(cached);
    }

    // Check if it's a private or special IP
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
            asn: "N/A".to_string(),
            prefix: ipv4_addr.to_string() + "/32",
            country_code: "N/A".to_string(),
            registry: "N/A".to_string(),
            name,
        };

        // Cache the result
        if let Ok(net) = asn_info.prefix.parse::<Ipv4Net>() {
            ASN_CACHE.insert(net, asn_info.clone());
        }

        return Ok(asn_info);
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

    let asn = parts[0].to_string();
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
                    as_parts[4].to_string()
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
    ASN_CACHE.insert(net, asn_info.clone());

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

    #[tokio::test]
    async fn test_lookup_private_ip() {
        let ip: Ipv4Addr = "192.168.1.1".parse().unwrap();
        let result = lookup_asn(ip, None).await;
        assert!(result.is_ok());
        let asn_info = result.unwrap();
        assert_eq!(asn_info.asn, "N/A");
        assert_eq!(asn_info.name, "Private Network");
    }

    #[tokio::test]
    async fn test_lookup_cgnat_ip() {
        let ip: Ipv4Addr = "100.64.0.1".parse().unwrap();
        let result = lookup_asn(ip, None).await;
        match &result {
            Ok(asn_info) => {
                assert_eq!(asn_info.asn, "N/A");
                assert_eq!(asn_info.name, "Carrier Grade NAT");
            }
            Err(e) => panic!("Expected Ok, got error: {:?}", e),
        }
    }

    #[tokio::test]
    async fn test_lookup_loopback() {
        let ip: Ipv4Addr = "127.0.0.1".parse().unwrap();
        let result = lookup_asn(ip, None).await;
        assert!(result.is_ok());
        let asn_info = result.unwrap();
        assert_eq!(asn_info.asn, "N/A");
        assert_eq!(asn_info.name, "Loopback");
    }

    #[tokio::test]
    async fn test_cache_usage() {
        // Clear cache
        ASN_CACHE.clear();

        let ip: Ipv4Addr = "10.0.0.1".parse().unwrap();

        // First lookup - should populate cache
        let result1 = lookup_asn(ip, None).await;
        assert!(result1.is_ok());

        // Second lookup - should use cache
        let result2 = lookup_asn(ip, None).await;
        assert!(result2.is_ok());
        assert_eq!(result1.unwrap().name, result2.unwrap().name);
    }
}
