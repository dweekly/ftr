//! Extract ISP information from traceroute path
//!
//! This module provides functionality to extract ISP information directly
//! from the traceroute path, avoiding expensive external API calls.

use crate::traceroute::{is_cgnat, is_internal_ip, ClassifiedHopInfo, IspInfo};
use std::net::IpAddr;

/// Extract ISP information from the traceroute path
///
/// This function identifies the user's ISP by finding the first public IP
/// in the traceroute path and using its ASN information. This is much faster
/// than making external HTTP requests.
///
/// The logic is:
/// 1. Find the first hop with a public IP (not private, not CGNAT)
/// 2. Use that hop's ASN as the ISP
/// 3. Use that IP as the public IP (or close to it)
pub fn extract_isp_from_path(hops: &[ClassifiedHopInfo]) -> Option<IspInfo> {
    // Find the first hop with a public IP and ASN info
    for hop in hops {
        if let Some(addr) = hop.addr {
            if let IpAddr::V4(ipv4) = addr {
                // Skip private and CGNAT addresses
                if is_internal_ip(&ipv4) || is_cgnat(&ipv4) {
                    continue;
                }

                // This is a public IP - check if we have ASN info
                if let Some(ref asn_info) = hop.asn_info {
                    if asn_info.asn != 0 {
                        return Some(IspInfo {
                            public_ip: addr,
                            asn: asn_info.asn,
                            name: asn_info.name.clone(),
                            hostname: hop.hostname.clone(),
                        });
                    }
                }
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traceroute::{AsnInfo, SegmentType};
    use std::net::Ipv4Addr;

    #[test]
    fn test_extract_isp_from_path() {
        let hops = vec![
            // LAN hop
            ClassifiedHopInfo {
                ttl: 1,
                segment: SegmentType::Lan,
                hostname: Some("router.local".to_string()),
                addr: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
                asn_info: None,
                rtt: None,
            },
            // ISP hop - this should be detected
            ClassifiedHopInfo {
                ttl: 2,
                segment: SegmentType::Isp,
                hostname: Some("gateway.isp.com".to_string()),
                addr: Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))),
                asn_info: Some(AsnInfo {
                    asn: 12345,
                    prefix: "203.0.113.0/24".to_string(),
                    country_code: "US".to_string(),
                    registry: "ARIN".to_string(),
                    name: "TEST-ISP".to_string(),
                }),
                rtt: None,
            },
        ];

        let isp = extract_isp_from_path(&hops);
        assert!(isp.is_some());

        let isp = isp.unwrap();
        assert_eq!(isp.asn, 12345);
        assert_eq!(isp.name, "TEST-ISP");
        assert_eq!(isp.public_ip, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)));
        assert_eq!(isp.hostname, Some("gateway.isp.com".to_string()));
    }

    #[test]
    fn test_skip_private_ips() {
        let hops = vec![
            // Private IP - should be skipped
            ClassifiedHopInfo {
                ttl: 1,
                segment: SegmentType::Lan,
                hostname: None,
                addr: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
                asn_info: None,
                rtt: None,
            },
            // CGNAT IP - should be skipped
            ClassifiedHopInfo {
                ttl: 2,
                segment: SegmentType::Isp,
                hostname: None,
                addr: Some(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))),
                asn_info: Some(AsnInfo {
                    asn: 12345,
                    prefix: "100.64.0.0/10".to_string(),
                    country_code: "US".to_string(),
                    registry: "ARIN".to_string(),
                    name: "CGNAT-ISP".to_string(),
                }),
                rtt: None,
            },
            // Public IP - should be used
            ClassifiedHopInfo {
                ttl: 3,
                segment: SegmentType::Isp,
                hostname: None,
                addr: Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
                asn_info: Some(AsnInfo {
                    asn: 15169,
                    prefix: "8.8.8.0/24".to_string(),
                    country_code: "US".to_string(),
                    registry: "ARIN".to_string(),
                    name: "GOOGLE".to_string(),
                }),
                rtt: None,
            },
        ];

        let isp = extract_isp_from_path(&hops);
        assert!(isp.is_some());

        let isp = isp.unwrap();
        assert_eq!(isp.asn, 15169);
        assert_eq!(isp.name, "GOOGLE");
    }
}
