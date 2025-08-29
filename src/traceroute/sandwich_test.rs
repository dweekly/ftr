/// Tests for sandwich logic that fills in Unknown/Transit segments
/// 
/// The sandwich logic ensures that hops between two segments of the same type
/// inherit that segment type. This handles cases where:
/// - Probes fail to respond but are clearly part of a network segment
/// - IPs lack ASN data but are positioned between known segments
/// - Transit networks have incomplete BGP information
/// 
/// Priority rules:
/// 1. ISP segments take precedence over Destination segments
/// 2. Only hops with addresses are affected (silent hops remain Unknown)
/// 3. LAN segments do not participate in sandwiching
#[cfg(test)]
mod tests {
    use super::super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    #[test]
    fn test_sandwich_logic_isp() {
        // Create a scenario: ISP -> Unknown -> ISP
        // The Unknown should become ISP
        let mut hops = vec![
            ClassifiedHopInfo {
                ttl: 1,
                segment: SegmentType::Isp,
                hostname: Some("hop1".to_string()),
                addr: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
                asn_info: None,
                rtt: Some(Duration::from_millis(5)),
            },
            ClassifiedHopInfo {
                ttl: 2,
                segment: SegmentType::Unknown,
                hostname: Some("hop2".to_string()),
                addr: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
                asn_info: None,
                rtt: Some(Duration::from_millis(10)),
            },
            ClassifiedHopInfo {
                ttl: 3,
                segment: SegmentType::Isp,
                hostname: Some("hop3".to_string()),
                addr: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3))),
                asn_info: None,
                rtt: Some(Duration::from_millis(15)),
            },
        ];

        super::super::FullyParallelAsyncEngine::apply_sandwich_logic(&mut hops);
        
        assert_eq!(hops[1].segment, SegmentType::Isp, "Unknown hop between ISP hops should become ISP");
    }

    #[test]
    fn test_sandwich_logic_destination() {
        // Create a scenario: Destination -> Transit -> Destination
        // The Transit should become Destination
        let mut hops = vec![
            ClassifiedHopInfo {
                ttl: 1,
                segment: SegmentType::Destination,
                hostname: Some("dest1".to_string()),
                addr: Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 1))),
                asn_info: None,
                rtt: Some(Duration::from_millis(5)),
            },
            ClassifiedHopInfo {
                ttl: 2,
                segment: SegmentType::Transit,
                hostname: Some("transit".to_string()),
                addr: Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 2))),
                asn_info: None,
                rtt: Some(Duration::from_millis(10)),
            },
            ClassifiedHopInfo {
                ttl: 3,
                segment: SegmentType::Destination,
                hostname: Some("dest2".to_string()),
                addr: Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 3))),
                asn_info: None,
                rtt: Some(Duration::from_millis(15)),
            },
        ];

        super::super::FullyParallelAsyncEngine::apply_sandwich_logic(&mut hops);
        
        assert_eq!(hops[1].segment, SegmentType::Destination, "Transit hop between Destination hops should become Destination");
    }

    #[test]
    fn test_sandwich_logic_no_address() {
        // Silent hops (no address) should not be changed
        let mut hops = vec![
            ClassifiedHopInfo {
                ttl: 1,
                segment: SegmentType::Isp,
                hostname: Some("hop1".to_string()),
                addr: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
                asn_info: None,
                rtt: Some(Duration::from_millis(5)),
            },
            ClassifiedHopInfo {
                ttl: 2,
                segment: SegmentType::Unknown,
                hostname: None,
                addr: None, // No address - silent hop
                asn_info: None,
                rtt: None,
            },
            ClassifiedHopInfo {
                ttl: 3,
                segment: SegmentType::Isp,
                hostname: Some("hop3".to_string()),
                addr: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3))),
                asn_info: None,
                rtt: Some(Duration::from_millis(15)),
            },
        ];

        super::super::FullyParallelAsyncEngine::apply_sandwich_logic(&mut hops);
        
        assert_eq!(hops[1].segment, SegmentType::Unknown, "Silent hop should remain Unknown");
    }

    #[test]
    fn test_sandwich_logic_multiple_unknowns() {
        // Test multiple consecutive unknown hops between ISP hops
        let mut hops = vec![
            ClassifiedHopInfo {
                ttl: 1,
                segment: SegmentType::Isp,
                hostname: Some("isp1".to_string()),
                addr: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
                asn_info: None,
                rtt: Some(Duration::from_millis(5)),
            },
            ClassifiedHopInfo {
                ttl: 2,
                segment: SegmentType::Unknown,
                hostname: None,
                addr: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
                asn_info: None,
                rtt: Some(Duration::from_millis(10)),
            },
            ClassifiedHopInfo {
                ttl: 3,
                segment: SegmentType::Transit,
                hostname: None,
                addr: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3))),
                asn_info: None,
                rtt: Some(Duration::from_millis(15)),
            },
            ClassifiedHopInfo {
                ttl: 4,
                segment: SegmentType::Unknown,
                hostname: None,
                addr: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4))),
                asn_info: None,
                rtt: Some(Duration::from_millis(20)),
            },
            ClassifiedHopInfo {
                ttl: 5,
                segment: SegmentType::Isp,
                hostname: Some("isp2".to_string()),
                addr: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))),
                asn_info: None,
                rtt: Some(Duration::from_millis(25)),
            },
        ];

        super::super::FullyParallelAsyncEngine::apply_sandwich_logic(&mut hops);
        
        assert_eq!(hops[1].segment, SegmentType::Isp, "First unknown between ISP hops should become ISP");
        assert_eq!(hops[2].segment, SegmentType::Isp, "Transit between ISP hops should become ISP");
        assert_eq!(hops[3].segment, SegmentType::Isp, "Second unknown between ISP hops should become ISP");
    }

    #[test]
    fn test_sandwich_logic_mixed_silent_and_responsive() {
        // Test mix of silent hops and responsive hops
        let mut hops = vec![
            ClassifiedHopInfo {
                ttl: 1,
                segment: SegmentType::Destination,
                hostname: Some("dest1".to_string()),
                addr: Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 1))),
                asn_info: None,
                rtt: Some(Duration::from_millis(5)),
            },
            ClassifiedHopInfo {
                ttl: 2,
                segment: SegmentType::Unknown,
                hostname: None,
                addr: None, // Silent hop
                asn_info: None,
                rtt: None,
            },
            ClassifiedHopInfo {
                ttl: 3,
                segment: SegmentType::Transit,
                hostname: Some("transit".to_string()),
                addr: Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 3))),
                asn_info: None,
                rtt: Some(Duration::from_millis(15)),
            },
            ClassifiedHopInfo {
                ttl: 4,
                segment: SegmentType::Destination,
                hostname: Some("dest2".to_string()),
                addr: Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 4))),
                asn_info: None,
                rtt: Some(Duration::from_millis(20)),
            },
        ];

        super::super::FullyParallelAsyncEngine::apply_sandwich_logic(&mut hops);
        
        assert_eq!(hops[1].segment, SegmentType::Unknown, "Silent hop should remain Unknown");
        assert_eq!(hops[2].segment, SegmentType::Destination, "Transit between Destination hops should become Destination");
    }

    #[test]
    fn test_sandwich_logic_edge_cases() {
        // Test edge cases: empty list, single hop, two hops
        
        // Empty list
        let mut empty_hops: Vec<ClassifiedHopInfo> = vec![];
        super::super::FullyParallelAsyncEngine::apply_sandwich_logic(&mut empty_hops);
        assert_eq!(empty_hops.len(), 0, "Empty list should remain empty");
        
        // Single hop
        let mut single_hop = vec![
            ClassifiedHopInfo {
                ttl: 1,
                segment: SegmentType::Unknown,
                hostname: None,
                addr: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
                asn_info: None,
                rtt: Some(Duration::from_millis(5)),
            },
        ];
        super::super::FullyParallelAsyncEngine::apply_sandwich_logic(&mut single_hop);
        assert_eq!(single_hop[0].segment, SegmentType::Unknown, "Single hop should not change");
        
        // Two hops - no sandwich possible
        let mut two_hops = vec![
            ClassifiedHopInfo {
                ttl: 1,
                segment: SegmentType::Isp,
                hostname: Some("isp".to_string()),
                addr: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
                asn_info: None,
                rtt: Some(Duration::from_millis(5)),
            },
            ClassifiedHopInfo {
                ttl: 2,
                segment: SegmentType::Unknown,
                hostname: None,
                addr: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
                asn_info: None,
                rtt: Some(Duration::from_millis(10)),
            },
        ];
        super::super::FullyParallelAsyncEngine::apply_sandwich_logic(&mut two_hops);
        assert_eq!(two_hops[1].segment, SegmentType::Unknown, "Two hops cannot form sandwich");
    }

    #[test]
    fn test_sandwich_logic_lan_not_affected() {
        // LAN segments should not participate in sandwiching
        let mut hops = vec![
            ClassifiedHopInfo {
                ttl: 1,
                segment: SegmentType::Lan,
                hostname: Some("router1".to_string()),
                addr: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
                asn_info: None,
                rtt: Some(Duration::from_millis(1)),
            },
            ClassifiedHopInfo {
                ttl: 2,
                segment: SegmentType::Unknown,
                hostname: None,
                addr: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
                asn_info: None,
                rtt: Some(Duration::from_millis(5)),
            },
            ClassifiedHopInfo {
                ttl: 3,
                segment: SegmentType::Lan,
                hostname: Some("router2".to_string()),
                addr: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 254))),
                asn_info: None,
                rtt: Some(Duration::from_millis(2)),
            },
        ];

        super::super::FullyParallelAsyncEngine::apply_sandwich_logic(&mut hops);
        
        // We don't sandwich between LAN hops (they're typically different networks)
        assert_eq!(hops[1].segment, SegmentType::Unknown, "Unknown between LAN hops should not be sandwiched");
    }

    #[test]
    fn test_sandwich_logic_isp_precedence() {
        // ISP should take precedence when a hop is between both ISP and Destination
        let mut hops = vec![
            ClassifiedHopInfo {
                ttl: 1,
                segment: SegmentType::Isp,
                hostname: Some("isp1".to_string()),
                addr: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
                asn_info: None,
                rtt: Some(Duration::from_millis(5)),
            },
            ClassifiedHopInfo {
                ttl: 2,
                segment: SegmentType::Unknown,
                hostname: Some("unknown".to_string()),
                addr: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
                asn_info: None,
                rtt: Some(Duration::from_millis(10)),
            },
            ClassifiedHopInfo {
                ttl: 3,
                segment: SegmentType::Isp,
                hostname: Some("isp2".to_string()),
                addr: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3))),
                asn_info: None,
                rtt: Some(Duration::from_millis(15)),
            },
            ClassifiedHopInfo {
                ttl: 4,
                segment: SegmentType::Destination,
                hostname: Some("dest".to_string()),
                addr: Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
                asn_info: None,
                rtt: Some(Duration::from_millis(20)),
            },
        ];

        super::super::FullyParallelAsyncEngine::apply_sandwich_logic(&mut hops);
        
        assert_eq!(hops[1].segment, SegmentType::Isp, "Unknown between ISP hops should become ISP even with Destination present");
    }
}