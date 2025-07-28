//! Core traceroute functionality and utilities

pub mod api;
pub mod config;
pub mod engine;
pub mod result;
pub mod types;

use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

// Re-export commonly used types
pub use api::{trace, trace_with_config, Traceroute};
pub use config::{TracerouteConfig, TracerouteConfigBuilder};
pub use engine::{TracerouteEngine, TracerouteError};
pub use result::{TracerouteProgress, TracerouteResult};
pub use types::{ClassifiedHopInfo, IspInfo, RawHopInfo};

/// Classification of a hop's network segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SegmentType {
    /// Local area network (private IP ranges)
    Lan,
    /// Internet Service Provider network
    Isp,
    /// Beyond the user's ISP (general internet)
    Beyond,
    /// Unknown segment type
    Unknown,
}

impl std::fmt::Display for SegmentType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SegmentType::Lan => write!(f, "LAN   "),
            SegmentType::Isp => write!(f, "ISP   "),
            SegmentType::Beyond => write!(f, "BEYOND"),
            SegmentType::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

/// Checks if an IP address is within private/internal ranges.
pub fn is_internal_ip(ip: &Ipv4Addr) -> bool {
    ip.is_private() || ip.is_loopback() || ip.is_link_local()
}

/// Checks if an IP is in the CGNAT range (100.64.0.0/10).
pub fn is_cgnat(ip: &Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 100 && (64..=127).contains(&octets[1])
}

/// Parse an ASN string into components
pub fn parse_asn(asn_str: &str) -> Option<(String, String, String)> {
    // Format: "AS13335 | 104.16.0.0/12 | US | ARIN | CLOUDFLARENET"
    let parts: Vec<&str> = asn_str.split(" | ").collect();
    if parts.len() >= 5 {
        Some((
            parts[0].to_string(),
            parts[1].to_string(),
            parts[4].to_string(),
        ))
    } else {
        None
    }
}

/// Represents ASN information for an IP address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AsnInfo {
    /// Autonomous System Number (e.g., "13335")
    pub asn: String,
    /// IP prefix/CIDR block (e.g., "104.16.0.0/12")
    pub prefix: String,
    /// Two-letter country code (e.g., "US")
    pub country_code: String,
    /// Regional Internet Registry (e.g., "ARIN")
    pub registry: String,
    /// AS name/organization (e.g., "CLOUDFLARENET")
    pub name: String,
}

/// Parse CIDR notation into Ipv4Net
pub fn parse_cidr(cidr: &str) -> Option<Ipv4Net> {
    cidr.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_segment_type_display() {
        assert_eq!(SegmentType::Lan.to_string(), "LAN   ");
        assert_eq!(SegmentType::Isp.to_string(), "ISP   ");
        assert_eq!(SegmentType::Beyond.to_string(), "BEYOND");
        assert_eq!(SegmentType::Unknown.to_string(), "UNKNOWN");
    }

    #[test]
    fn test_is_internal_ip() {
        // Private ranges
        assert!(is_internal_ip(&"192.168.1.1".parse().unwrap()));
        assert!(is_internal_ip(&"10.0.0.1".parse().unwrap()));
        assert!(is_internal_ip(&"172.16.0.1".parse().unwrap()));
        assert!(is_internal_ip(&"172.31.255.255".parse().unwrap()));

        // Loopback
        assert!(is_internal_ip(&"127.0.0.1".parse().unwrap()));
        assert!(is_internal_ip(&"127.255.255.255".parse().unwrap()));

        // Link-local
        assert!(is_internal_ip(&"169.254.1.1".parse().unwrap()));

        // Public IPs
        assert!(!is_internal_ip(&"8.8.8.8".parse().unwrap()));
        assert!(!is_internal_ip(&"1.1.1.1".parse().unwrap()));
        assert!(!is_internal_ip(&"172.32.0.1".parse().unwrap())); // Just outside private range
    }

    #[test]
    fn test_is_cgnat() {
        // CGNAT range: 100.64.0.0/10
        assert!(is_cgnat(&"100.64.0.0".parse().unwrap()));
        assert!(is_cgnat(&"100.64.0.1".parse().unwrap()));
        assert!(is_cgnat(&"100.127.255.255".parse().unwrap()));
        assert!(is_cgnat(&"100.100.100.100".parse().unwrap()));

        // Just outside CGNAT range
        assert!(!is_cgnat(&"100.63.255.255".parse().unwrap()));
        assert!(!is_cgnat(&"100.128.0.0".parse().unwrap()));
        assert!(!is_cgnat(&"99.64.0.0".parse().unwrap()));
        assert!(!is_cgnat(&"101.64.0.0".parse().unwrap()));

        // Other IPs
        assert!(!is_cgnat(&"8.8.8.8".parse().unwrap()));
        assert!(!is_cgnat(&"192.168.1.1".parse().unwrap()));
    }

    #[test]
    fn test_parse_asn() {
        let asn_str = "AS13335 | 104.16.0.0/12 | US | ARIN | CLOUDFLARENET";
        let result = parse_asn(asn_str);
        assert_eq!(
            result,
            Some((
                "AS13335".to_string(),
                "104.16.0.0/12".to_string(),
                "CLOUDFLARENET".to_string()
            ))
        );

        // Invalid format
        assert_eq!(parse_asn("invalid"), None);
        assert_eq!(parse_asn("AS123 | incomplete"), None);
    }

    #[test]
    fn test_parse_cidr() {
        assert!(parse_cidr("192.168.0.0/16").is_some());
        assert!(parse_cidr("10.0.0.0/8").is_some());
        assert!(parse_cidr("172.16.0.0/12").is_some());

        // Invalid CIDR
        assert!(parse_cidr("invalid").is_none());
        assert!(parse_cidr("192.168.0.0/33").is_none()); // Invalid prefix length
        assert!(parse_cidr("256.0.0.0/8").is_none()); // Invalid IP
    }

    #[test]
    fn test_asn_info() {
        let asn_info = AsnInfo {
            asn: "13335".to_string(),
            prefix: "104.16.0.0/12".to_string(),
            country_code: "US".to_string(),
            registry: "ARIN".to_string(),
            name: "CLOUDFLARENET".to_string(),
        };

        assert_eq!(asn_info.asn, "13335");
        assert_eq!(asn_info.country_code, "US");

        // Test Clone
        let cloned = asn_info.clone();
        assert_eq!(cloned, asn_info);
    }
}
