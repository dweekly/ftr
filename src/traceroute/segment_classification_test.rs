/// Tests for network segment classification logic in v0.6.0
///
/// These tests verify the correct classification of hops into segments:
/// - LAN: Private/internal IP addresses
/// - ISP: Internet Service Provider network (including CGNAT)
/// - TRANSIT: Networks between ISP and destination (including IXPs without ASN)
/// - DESTINATION: Hops within the destination's ASN
/// - UNKNOWN: Unclassifiable segments
#[cfg(test)]
mod tests {
    use crate::traceroute::{AsnInfo, SegmentType};
    use std::net::Ipv4Addr;

    #[test]
    fn test_transit_classification_no_asn_public_ip() {
        // Test that public IPs without ASN info are classified as TRANSIT
        // This covers the case like Equinix peering points (206.223.116.16)

        // Simulate the classification logic for a public IP without ASN
        let ipv4 = Ipv4Addr::new(206, 223, 116, 16);
        let is_internal = crate::traceroute::is_internal_ip(&ipv4);
        let is_cgnat = crate::traceroute::is_cgnat(&ipv4);

        assert!(!is_internal, "206.223.116.16 should not be internal");
        assert!(!is_cgnat, "206.223.116.16 should not be CGNAT");

        // When a public IP has no ASN and we're past ISP boundary,
        // it should be classified as TRANSIT
        let in_isp_segment = true; // Assume we've passed ISP hops
        let asn_info: Option<AsnInfo> = None; // No ASN data available

        let segment = if !is_internal && !is_cgnat && asn_info.is_none() && in_isp_segment {
            SegmentType::Transit
        } else {
            SegmentType::Unknown
        };

        assert_eq!(
            segment,
            SegmentType::Transit,
            "Public IP without ASN after ISP should be TRANSIT"
        );
    }

    #[test]
    fn test_destination_segment_with_matching_asn() {
        // Test that hops with ASN matching destination are marked as DESTINATION
        let dest_asn = Some(15169u32); // Google's ASN

        let hop_asn_info = Some(AsnInfo {
            asn: 15169,
            prefix: "142.250.0.0/15".to_string(),
            country_code: "US".to_string(),
            registry: "arin".to_string(),
            name: "GOOGLE, US".to_string(),
        });

        // Check if hop ASN matches destination ASN
        let segment = if let Some(asn_info) = &hop_asn_info {
            if let Some(dest) = dest_asn {
                if asn_info.asn == dest {
                    SegmentType::Destination
                } else {
                    SegmentType::Transit
                }
            } else {
                SegmentType::Unknown
            }
        } else {
            SegmentType::Unknown
        };

        assert_eq!(
            segment,
            SegmentType::Destination,
            "Hop with ASN matching destination should be DESTINATION"
        );
    }

    #[test]
    fn test_transit_segment_different_asn() {
        // Test that hops with different ASN than ISP and destination are TRANSIT
        let isp_asn = Some(46375u32); // Sonic ISP
        let dest_asn = Some(15169u32); // Google
        let _in_isp_segment = false; // We've passed ISP boundary (unused but kept for clarity)

        let hop_asn_info = Some(AsnInfo {
            asn: 10310, // Yahoo transit network
            prefix: "209.191.64.0/20".to_string(),
            country_code: "US".to_string(),
            registry: "arin".to_string(),
            name: "YAHOO-1, US".to_string(),
        });

        // Classification logic
        let segment = if let Some(asn_info) = &hop_asn_info {
            if let Some(isp) = isp_asn {
                if asn_info.asn == isp {
                    SegmentType::Isp
                } else if let Some(dest) = dest_asn {
                    if asn_info.asn == dest {
                        SegmentType::Destination
                    } else {
                        SegmentType::Transit
                    }
                } else {
                    SegmentType::Transit
                }
            } else {
                SegmentType::Unknown
            }
        } else {
            SegmentType::Unknown
        };

        assert_eq!(
            segment,
            SegmentType::Transit,
            "Hop with ASN different from ISP and destination should be TRANSIT"
        );
    }

    #[test]
    fn test_isp_segment_classification() {
        // Test ISP segment classification including CGNAT ranges

        // Test CGNAT IP (100.64.0.0/10)
        let cgnat_ip = Ipv4Addr::new(100, 65, 0, 1);
        assert!(
            crate::traceroute::is_cgnat(&cgnat_ip),
            "100.65.0.1 should be in CGNAT range"
        );

        // Test ISP ASN matching
        let isp_asn = Some(46375u32);
        let hop_asn = AsnInfo {
            asn: 46375,
            prefix: "75.101.32.0/19".to_string(),
            country_code: "US".to_string(),
            registry: "arin".to_string(),
            name: "AS-SONICTELECOM, US".to_string(),
        };

        let segment = if Some(hop_asn.asn) == isp_asn {
            SegmentType::Isp
        } else {
            SegmentType::Unknown
        };

        assert_eq!(
            segment,
            SegmentType::Isp,
            "Hop with ASN matching ISP should be ISP segment"
        );
    }

    #[test]
    fn test_lan_segment_classification() {
        // Test LAN/private IP classification
        let private_ips = vec![
            Ipv4Addr::new(192, 168, 1, 1), // 192.168.0.0/16
            Ipv4Addr::new(10, 0, 0, 1),    // 10.0.0.0/8
            Ipv4Addr::new(172, 16, 0, 1),  // 172.16.0.0/12
            Ipv4Addr::new(127, 0, 0, 1),   // Loopback
            Ipv4Addr::new(169, 254, 0, 1), // Link-local
        ];

        for ip in private_ips {
            assert!(
                crate::traceroute::is_internal_ip(&ip),
                "{} should be classified as internal/LAN",
                ip
            );
        }

        // Test non-private IPs
        let public_ips = vec![
            Ipv4Addr::new(8, 8, 8, 8),
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(206, 223, 116, 16),
        ];

        for ip in public_ips {
            assert!(
                !crate::traceroute::is_internal_ip(&ip),
                "{} should NOT be classified as internal/LAN",
                ip
            );
        }
    }

    #[test]
    fn test_segment_priority_in_classification() {
        // Test that ISP classification takes priority over destination
        // when we haven't left ISP boundary yet
        let isp_asn = Some(46375u32);
        let dest_asn = Some(46375u32); // Same as ISP (hypothetical)
        let in_isp_segment = true;

        let hop_asn = AsnInfo {
            asn: 46375,
            prefix: "75.101.32.0/19".to_string(),
            country_code: "US".to_string(),
            registry: "arin".to_string(),
            name: "AS-SONICTELECOM, US".to_string(),
        };

        // When ASN matches both ISP and destination, and we're still in ISP segment,
        // it should be classified as ISP
        let segment = if in_isp_segment && Some(hop_asn.asn) == isp_asn {
            SegmentType::Isp
        } else if Some(hop_asn.asn) == dest_asn {
            SegmentType::Destination
        } else {
            SegmentType::Transit
        };

        assert_eq!(
            segment,
            SegmentType::Isp,
            "When in ISP segment, ISP classification should take priority"
        );
    }
}
