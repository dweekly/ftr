//! ASN lookup functionality using Team Cymru's whois service

use crate::asn::cache::AsnCache;
use crate::dns::resolver;
use crate::traceroute::{is_cgnat, is_internal_ip, AsnInfo};
use ip_network::Ipv4Network;
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
        if let Ok(net) = asn_info.prefix.parse::<Ipv4Network>() {
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

    // Query Team Cymru DNS
    let octets = ipv4_addr.octets();
    let query = format!(
        "{}.{}.{}.{}.origin.asn.cymru.com",
        octets[3], octets[2], octets[1], octets[0]
    );

    let txts = resolver::resolve_txt(&query)
        .await
        .map_err(|e| AsnLookupError::DnsError(e.to_string()))?;

    let txt_data = txts.first().ok_or(AsnLookupError::NotFound)?;

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

    // Parse prefix to create Ipv4Network
    let net = prefix
        .parse::<Ipv4Network>()
        .map_err(|_| AsnLookupError::InvalidFormat)?;

    // Query for AS name
    let as_query = format!("AS{asn}.asn.cymru.com");
    let name = match resolver::resolve_txt(&as_query).await {
        Ok(as_txts) => {
            if let Some(as_txt) = as_txts.first() {
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

#[cfg(test)]
#[path = "lookup_tests.rs"]
mod tests;
