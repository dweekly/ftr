//! ASN lookup functionality using Team Cymru's whois service

use crate::asn::cache::AsnCache;
use crate::dns::resolver;
use crate::traceroute::{AsnInfo, is_cgnat, is_internal_ip};
use ip_network::{Ipv4Network, Ipv6Network};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Error type for ASN lookup operations
///
/// This enum is `#[non_exhaustive]`: new error variants may be added in
/// minor releases, so downstream matches must include a wildcard arm.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
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

/// Parsed fields of a Team Cymru origin/origin6 TXT payload.
///
/// Both the v4 (`origin.asn.cymru.com`) and v6 (`origin6.asn.cymru.com`)
/// zones use the same payload format:
/// `"AS | prefix | CC | registry | allocated"`
/// (<https://www.team-cymru.com/ip-asn-mapping>).
struct CymruOrigin {
    asn: u32,
    prefix: String,
    country_code: String,
    registry: String,
}

/// Parse a Cymru origin TXT payload into its fields.
///
/// Multi-origin prefixes list several ASNs space-separated in the first
/// field (e.g. `"15169 36040 | ..."`); the first ASN is used.
fn parse_cymru_origin_txt(txt: &str) -> Result<CymruOrigin, AsnLookupError> {
    let parts: Vec<&str> = txt.split('|').map(str::trim).collect();
    if parts.len() < 3 {
        return Err(AsnLookupError::InvalidFormat);
    }

    // Parse ASN as u32, handling a potential "AS" prefix and taking the
    // first ASN of a multi-origin list.
    let asn_str = parts[0]
        .split_whitespace()
        .next()
        .unwrap_or("")
        .trim_start_matches("AS");
    let asn = asn_str.parse::<u32>().unwrap_or(0);

    Ok(CymruOrigin {
        asn,
        prefix: parts[1].to_string(),
        country_code: parts[2].to_string(),
        registry: if parts.len() > 3 {
            parts[3].to_string()
        } else {
            String::new()
        },
    })
}

/// Query a Cymru origin zone name and parse the first TXT payload.
async fn query_cymru_origin(query: &str) -> Result<CymruOrigin, AsnLookupError> {
    let txts = resolver::resolve_txt(query)
        .await
        .map_err(|e| AsnLookupError::DnsError(e.to_string()))?;
    let txt_data = txts.first().ok_or(AsnLookupError::NotFound)?;
    parse_cymru_origin_txt(txt_data)
}

/// Look up the AS organization name via `AS{asn}.asn.cymru.com`.
///
/// Returns an empty string on any failure: the name is display-only
/// enrichment and must never fail the whole lookup.
async fn lookup_as_name(asn: u32, country_code: &str) -> String {
    let as_query = format!("AS{asn}.asn.cymru.com");
    match resolver::resolve_txt(&as_query).await {
        Ok(as_txts) => {
            if let Some(as_txt) = as_txts.first() {
                let as_parts: Vec<&str> = as_txt.split('|').map(str::trim).collect();
                if as_parts.len() >= 5 {
                    // Format is: ASN | CC | Registry | Allocated | AS Name
                    let mut as_name = as_parts[4].to_string();
                    // Team Cymru often includes ", CC" at the end of the name - remove it
                    if as_name.ends_with(&format!(", {country_code}")) {
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
    }
}

/// Build the Team Cymru `origin6.asn.cymru.com` query name for an IPv6
/// address: all 32 hex nibbles of the fully expanded address become labels,
/// least-significant nibble first
/// (<https://www.team-cymru.com/ip-asn-mapping>).
///
/// e.g. `2001:4860:4860::8888` becomes
/// `8.8.8.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.6.8.4.0.6.8.4.1.0.0.2.origin6.asn.cymru.com`.
///
/// Validated against the live zone by `examples/spike_asn6.rs`.
fn origin6_query_name(addr: &Ipv6Addr) -> String {
    const SUFFIX: &str = "origin6.asn.cymru.com";
    let mut name = String::with_capacity(32 * 2 + SUFFIX.len());
    for byte in addr.octets().iter().rev() {
        // Low nibble first: it is the less significant of the pair and the
        // whole name runs least-significant-nibble first.
        name.push_str(&format!("{:x}.{:x}.", byte & 0x0f, byte >> 4));
    }
    name.push_str(SUFFIX);
    name
}

/// Classify a non-routable IPv6 address, returning the human-readable name
/// used in the typed "private/reserved" [`AsnInfo`] outcome (matching the
/// v4 RFC 1918 handling), or `None` if the address is globally routable and
/// therefore worth a Cymru query.
///
/// Note: v4-mapped addresses (`::ffff:0:0/96`) are handled separately in
/// [`lookup_asn_v6_with_cache`], which defers to the v4 path for the
/// embedded address.
///
/// Ranges (IANA IPv6 Special-Purpose Address Registry):
/// - `::1/128` loopback (RFC 4291 §2.5.3)
/// - `::/128` unspecified (RFC 4291 §2.5.2)
/// - `fe80::/10` link-local unicast (RFC 4291 §2.5.6)
/// - `fc00::/7` unique local addresses (RFC 4193) — the v6 analog of RFC 1918
/// - `2001:db8::/32` documentation (RFC 3849)
/// - `ff00::/8` multicast (RFC 4291 §2.7)
fn special_ipv6_name(addr: &Ipv6Addr) -> Option<&'static str> {
    let seg = addr.segments();
    if addr.is_loopback() {
        Some("Loopback")
    } else if (seg[0] & 0xfe00) == 0xfc00 {
        // fc00::/7 unique local: mask the top 7 bits of the first hextet
        Some("Private Network")
    } else if addr.is_unspecified()
        // fe80::/10 link-local: mask the top 10 bits of the first hextet
        || (seg[0] & 0xffc0) == 0xfe80
        // 2001:db8::/32 documentation: exact first two hextets
        || (seg[0] == 0x2001 && seg[1] == 0xdb8)
        // ff00::/8 multicast: mask the top 8 bits of the first hextet
        || (seg[0] & 0xff00) == 0xff00
    {
        Some("Special Use")
    } else {
        None
    }
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
    let origin = query_cymru_origin(&query).await?;

    // Parse prefix to create Ipv4Network
    let net = origin
        .prefix
        .parse::<Ipv4Network>()
        .map_err(|_| AsnLookupError::InvalidFormat)?;

    // Query for AS name
    let name = lookup_as_name(origin.asn, &origin.country_code).await;

    let asn_info = AsnInfo {
        asn: origin.asn,
        prefix: origin.prefix,
        country_code: origin.country_code,
        registry: origin.registry,
        name,
    };

    // Cache the result
    let cache_write = cache.write().await;
    cache_write.insert(net, asn_info.clone());

    Ok(asn_info)
}

/// Performs IPv6 ASN lookup via Team Cymru's `origin6.asn.cymru.com` zone
/// with injected cache (Internal use only - users should use AsnLookup
/// service)
pub(crate) async fn lookup_asn_v6_with_cache(
    ipv6_addr: Ipv6Addr,
    cache: &Arc<RwLock<AsnCache>>,
) -> Result<AsnInfo, AsnLookupError> {
    // v4-mapped addresses (::ffff:0:0/96, RFC 4291 §2.5.5.2) carry an
    // embedded IPv4 address: defer to the v4 path (including its RFC 1918
    // handling) so ::ffff:8.8.8.8 and 8.8.8.8 resolve identically.
    if let Some(v4) = ipv6_addr.to_ipv4_mapped() {
        return lookup_asn_with_cache(v4, cache).await;
    }

    // Check for non-routable ranges first, before cache — same typed
    // "private/reserved" outcome as the v4 special-IP handling.
    if let Some(name) = special_ipv6_name(&ipv6_addr) {
        let asn_info = AsnInfo {
            asn: 0, // 0 indicates N/A for private/special IPs
            prefix: format!("{ipv6_addr}/128"),
            country_code: "N/A".to_string(),
            registry: "N/A".to_string(),
            name: name.to_string(),
        };

        // Cache the result
        if let Ok(net) = asn_info.prefix.parse::<Ipv6Network>() {
            let cache_write = cache.write().await;
            cache_write.insert_ipv6(net, asn_info.clone());
        }

        return Ok(asn_info);
    }

    // Check cache for routable IPs
    {
        let cache_read = cache.read().await;
        if let Some(cached) = cache_read.get_ipv6(&ipv6_addr) {
            return Ok(cached);
        }
    }

    // Query Team Cymru DNS (origin6 zone, nibble-reversed name)
    let origin = query_cymru_origin(&origin6_query_name(&ipv6_addr)).await?;

    // Parse prefix to create Ipv6Network
    let net = origin
        .prefix
        .parse::<Ipv6Network>()
        .map_err(|_| AsnLookupError::InvalidFormat)?;

    // Query for AS name
    let name = lookup_as_name(origin.asn, &origin.country_code).await;

    let asn_info = AsnInfo {
        asn: origin.asn,
        prefix: origin.prefix,
        country_code: origin.country_code,
        registry: origin.registry,
        name,
    };

    // Cache the result
    let cache_write = cache.write().await;
    cache_write.insert_ipv6(net, asn_info.clone());

    Ok(asn_info)
}

#[cfg(test)]
#[path = "lookup_tests.rs"]
mod tests;
