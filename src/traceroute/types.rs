//! Core types for traceroute operations

use crate::traceroute::{AsnInfo, SegmentType};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::time::Duration;

/// Intermediate hop information collected during traceroute.
#[derive(Debug, Clone)]
pub struct RawHopInfo {
    /// Time-to-live value
    pub ttl: u8,
    /// IP address of the hop
    pub addr: Option<IpAddr>,
    /// Round-trip time
    pub rtt: Option<Duration>,
}

/// Final hop information with ASN data and classification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassifiedHopInfo {
    /// Time-to-live value
    pub ttl: u8,
    /// Network segment classification
    pub segment: SegmentType,
    /// Reverse DNS hostname
    pub hostname: Option<String>,
    /// IP address of the hop
    pub addr: Option<IpAddr>,
    /// ASN information for this hop
    pub asn_info: Option<AsnInfo>,
    /// Round-trip time
    pub rtt: Option<Duration>,
}

impl ClassifiedHopInfo {
    /// Check if this hop reached the destination
    pub fn is_destination(&self, target: IpAddr) -> bool {
        self.addr == Some(target)
    }

    /// Get RTT in milliseconds
    pub fn rtt_ms(&self) -> Option<f64> {
        self.rtt.map(|d| d.as_secs_f64() * 1000.0)
    }
}

/// ISP information detected from public IP
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IspInfo {
    /// Public IP address
    pub public_ip: IpAddr,
    /// ASN number
    pub asn: String,
    /// ISP name
    pub name: String,
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
            asn: "AS12345".to_string(),
            name: "Example ISP".to_string(),
        };
        assert_eq!(isp.asn, "AS12345");
        assert_eq!(isp.name, "Example ISP");
    }
}
