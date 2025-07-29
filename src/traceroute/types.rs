//! Core types for traceroute operations

use crate::traceroute::{AsnInfo, SegmentType};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::time::Duration;

/// Intermediate hop information collected during traceroute
///
/// This represents raw probe response data before enrichment with
/// ASN information and network classification.
#[derive(Debug, Clone)]
pub struct RawHopInfo {
    /// Time-to-live value
    pub ttl: u8,
    /// IP address of the hop (None if no response)
    pub addr: Option<IpAddr>,
    /// Round-trip time
    pub rtt: Option<Duration>,
}

/// Complete hop information with ASN data and network classification
///
/// This is the enriched hop data that includes reverse DNS, ASN information,
/// and network segment classification.
///
/// # Examples
///
/// ```
/// # use ftr::{ClassifiedHopInfo, SegmentType};
/// # use std::net::IpAddr;
/// # let hop = ClassifiedHopInfo {
/// #     ttl: 10,
/// #     segment: SegmentType::Isp,
/// #     hostname: Some("router.example.com".to_string()),
/// #     addr: Some("8.8.8.8".parse().unwrap()),
/// #     asn_info: None,
/// #     rtt: Some(std::time::Duration::from_millis(25)),
/// # };
/// if let Some(addr) = hop.addr {
///     println!("Hop {}: {} ({:?})", hop.ttl, addr, hop.hostname);
///     if let Some(asn) = &hop.asn_info {
///         println!("  ASN: {} - {}", asn.asn, asn.name);
///     }
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassifiedHopInfo {
    /// Time-to-live value
    pub ttl: u8,
    /// Network segment classification (LAN, ISP, etc.)
    pub segment: SegmentType,
    /// Reverse DNS hostname if available
    pub hostname: Option<String>,
    /// IP address of the hop (None if no response)
    pub addr: Option<IpAddr>,
    /// ASN information for this hop
    pub asn_info: Option<AsnInfo>,
    /// Round-trip time
    pub rtt: Option<Duration>,
}

impl ClassifiedHopInfo {
    /// Check if this hop reached the destination
    ///
    /// Returns true if this hop's IP address matches the target IP.
    pub fn is_destination(&self, target: IpAddr) -> bool {
        self.addr == Some(target)
    }

    /// Get RTT in milliseconds
    ///
    /// Converts the Duration RTT to floating-point milliseconds for display.
    pub fn rtt_ms(&self) -> Option<f64> {
        self.rtt.map(|d| d.as_secs_f64() * 1000.0)
    }
}

/// ISP information detected from public IP
///
/// Contains information about the user's Internet Service Provider,
/// detected by looking up the public IP address.
///
/// # Examples
///
/// ```
/// # use ftr::IspInfo;
/// # use std::net::IpAddr;
/// let isp = IspInfo {
///     public_ip: "1.2.3.4".parse().unwrap(),
///     asn: 12345,
///     name: "Example ISP".to_string(),
/// };
/// println!("Connected via {} (AS{})", isp.name, isp.asn);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IspInfo {
    /// Public IP address
    pub public_ip: IpAddr,
    /// ASN number (e.g., 12345) - use 0 for N/A
    pub asn: u32,
    /// ISP/Organization name
    pub name: String,
    /// Reverse DNS hostname of the public IP (if available)
    pub hostname: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_raw_hop_info() {
        let hop = RawHopInfo {
            ttl: 5,
            addr: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            rtt: Some(Duration::from_millis(10)),
        };
        assert_eq!(hop.ttl, 5);
        assert!(hop.addr.is_some());
        assert_eq!(hop.rtt.unwrap().as_millis(), 10);
    }

    #[test]
    fn test_classified_hop_info() {
        let hop = ClassifiedHopInfo {
            ttl: 10,
            segment: SegmentType::Isp,
            hostname: Some("router.example.com".to_string()),
            addr: Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
            asn_info: None,
            rtt: Some(Duration::from_millis(25)),
        };

        assert_eq!(hop.ttl, 10);
        assert_eq!(hop.segment, SegmentType::Isp);
        assert_eq!(hop.rtt_ms(), Some(25.0));
        assert!(!hop.is_destination(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
        assert!(hop.is_destination(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
    }

    #[test]
    fn test_isp_info() {
        let isp = IspInfo {
            public_ip: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            asn: 12345,
            name: "Example ISP".to_string(),
            hostname: Some("customer.example-isp.com".to_string()),
        };
        assert_eq!(isp.asn, 12345);
        assert_eq!(isp.name, "Example ISP");
    }
}
