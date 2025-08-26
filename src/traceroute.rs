//! Core traceroute functionality and utilities
//!
//! This module provides the main traceroute implementation including:
//! - High-level API functions ([`trace`], [`trace_with_config`])
//! - Configuration types ([`TracerouteConfig`], [`TracerouteConfigBuilder`])
//! - Result types ([`TracerouteResult`], [`TracerouteProgress`])
//! - Error handling ([`TracerouteError`])
//!
//! # Error Handling
//!
//! All traceroute operations return a `Result<T, TracerouteError>` where
//! [`TracerouteError`] is an enum providing structured error information:
//!
//! - **`InsufficientPermissions`** - Includes what permissions are needed and suggestions
//! - **`NotImplemented`** - Feature not yet implemented (e.g., TCP traceroute)
//! - **`Ipv6NotSupported`** - IPv6 targets not yet supported
//! - **`ResolutionError`** - DNS resolution failed
//! - **`SocketError`** - Socket creation/operation failed
//! - **`ConfigError`** - Invalid configuration
//! - **`ProbeSendError`** - Failed to send probe packet
//!
//! This design allows library users to handle errors programmatically without
//! parsing error strings.

pub mod async_api;
pub mod async_engine;
pub mod config;
pub mod error;
pub mod fully_parallel_async_engine;
pub mod isp_from_path;
pub mod result;
pub mod types;

#[cfg(test)]
mod caching_test;

use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

// Re-export commonly used types
pub use async_api::{
    trace_async as trace, trace_with_config_async as trace_with_config,
    AsyncTraceroute as Traceroute,
};
pub use config::{TimingConfig, TracerouteConfig, TracerouteConfigBuilder};
pub use error::TracerouteError;
pub use result::{TracerouteProgress, TracerouteResult};
pub use types::{ClassifiedHopInfo, IspInfo, RawHopInfo};

/// Classification of a hop's network segment
///
/// Used to categorize network hops based on their location relative
/// to the user's network topology.
///
/// # Examples
///
/// ```
/// use ftr::SegmentType;
///
/// let segment = SegmentType::Isp;
/// println!("Hop is in the {} segment", segment);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SegmentType {
    /// Local area network (private IP ranges like 192.168.x.x)
    Lan,
    /// Internet Service Provider network
    Isp,
    /// After ISP, across ASNs that differ from destination's ASN
    Transit,
    /// Within the destination's ASN
    Destination,
    /// Unknown or unclassified segment
    Unknown,
}

impl std::fmt::Display for SegmentType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SegmentType::Lan => write!(f, "LAN   "),
            SegmentType::Isp => write!(f, "ISP   "),
            SegmentType::Transit => write!(f, "TRANSIT"),
            SegmentType::Destination => write!(f, "DESTINATION"),
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

/// Autonomous System Number (ASN) information for an IP address
///
/// Contains details about the network organization that owns a particular
/// IP address range. This information is retrieved from IPtoASN.com.
///
/// # Examples
///
/// ```
/// # use ftr::AsnInfo;
/// let asn = AsnInfo {
///     asn: 15169,
///     prefix: "8.8.8.0/24".to_string(),
///     country_code: "US".to_string(),
///     registry: "ARIN".to_string(),
///     name: "GOOGLE".to_string(),
/// };
///
/// // Use the display_asn method for consistent formatting
/// println!("{} - {} ({})", asn.display_asn(), asn.name, asn.country_code);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AsnInfo {
    /// Autonomous System Number (e.g., 13335)
    ///
    /// The numeric ASN without "AS" prefix. 0 indicates N/A (private/special IPs).
    /// To display: if asn != 0 { format!("AS{}", asn) } else { "N/A" }
    pub asn: u32,
    /// IP prefix/CIDR block (e.g., "104.16.0.0/12")
    pub prefix: String,
    /// Two-letter country code (e.g., "US")
    pub country_code: String,
    /// Regional Internet Registry (e.g., "ARIN", "RIPE", "APNIC")
    pub registry: String,
    /// AS name/organization (e.g., "CLOUDFLARENET", "GOOGLE")
    pub name: String,
}

impl AsnInfo {
    /// Get the display string for the ASN
    ///
    /// Returns "AS12345" format for valid ASNs, or "N/A" for private/special IPs.
    pub fn display_asn(&self) -> String {
        if self.asn != 0 {
            format!("AS{}", self.asn)
        } else {
            "N/A".to_string()
        }
    }
}

/// Parse CIDR notation into Ipv4Net
pub fn parse_cidr(cidr: &str) -> Option<Ipv4Net> {
    cidr.parse().ok()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_segment_type_display() {
        assert_eq!(SegmentType::Lan.to_string(), "LAN   ");
        assert_eq!(SegmentType::Isp.to_string(), "ISP   ");
        assert_eq!(SegmentType::Transit.to_string(), "TRANSIT");
        assert_eq!(SegmentType::Destination.to_string(), "DESTINATION");
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
            asn: 13335,
            prefix: "104.16.0.0/12".to_string(),
            country_code: "US".to_string(),
            registry: "ARIN".to_string(),
            name: "CLOUDFLARENET".to_string(),
        };

        assert_eq!(asn_info.asn, 13335);
        assert_eq!(asn_info.country_code, "US");
        assert_eq!(asn_info.display_asn(), "AS13335");

        // Test Clone
        let cloned = asn_info.clone();
        assert_eq!(cloned, asn_info);
    }

    #[test]
    fn test_asn_info_display() {
        // Test normal ASN
        let asn_info = AsnInfo {
            asn: 12345,
            prefix: "10.0.0.0/8".to_string(),
            country_code: "US".to_string(),
            registry: "ARIN".to_string(),
            name: "EXAMPLE".to_string(),
        };
        assert_eq!(asn_info.display_asn(), "AS12345");

        // Test N/A ASN (private/special IPs)
        let private_asn = AsnInfo {
            asn: 0,
            prefix: "192.168.0.0/16".to_string(),
            country_code: "".to_string(),
            registry: "".to_string(),
            name: "Private Use".to_string(),
        };
        assert_eq!(private_asn.display_asn(), "N/A");
    }
}
