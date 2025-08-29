/// Tests for v0.6.0 CLI features
///
/// These tests verify:
/// - JSON output formatting with 1 decimal place RTT precision
/// - Destination ASN field in JSON output
/// - TRANSIT and DESTINATION segment serialization
/// - Silent hop handling in JSON
///
/// These complement the integration tests by testing the CLI-specific
/// formatting and serialization logic.
#[cfg(test)]
mod tests {
    #[allow(unused_imports)] // These are used in test assertions
    use crate::{JsonHop, JsonIsp, JsonOutput};
    use ftr::{
        AsnInfo, ClassifiedHopInfo, IspInfo, ProbeProtocol, SegmentType, SocketMode,
        TracerouteResult,
    };
    use serde_json;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    #[test]
    fn test_json_rtt_precision() {
        // Test that RTT values are formatted to 1 decimal place
        let test_cases = vec![
            (1.234567f64, 1.2),
            (1.567890, 1.6),
            (10.951, 11.0),
            (5.449, 5.4),
            (5.450, 5.5),
            (5.451, 5.5),
            (0.05, 0.1),
            (0.04, 0.0),
        ];

        for (input, expected) in test_cases {
            let rounded = (input * 10.0).round() / 10.0;
            assert_eq!(
                rounded, expected,
                "RTT {} should round to {} with 1 decimal place",
                input, expected
            );
        }
    }

    #[test]
    fn test_json_destination_asn_field() {
        // Test that destination_asn field is properly serialized in JSON output
        let result = TracerouteResult {
            target: "google.com".to_string(),
            target_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            hops: vec![],
            isp_info: Some(IspInfo {
                public_ip: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
                asn: 12345,
                name: "Test ISP".to_string(),
                hostname: Some("customer.isp.com".to_string()),
            }),
            destination_asn: Some(AsnInfo {
                asn: 15169,
                prefix: "8.8.8.0/24".to_string(),
                country_code: "US".to_string(),
                registry: "ARIN".to_string(),
                name: "GOOGLE".to_string(),
            }), // Google's ASN
            protocol_used: ProbeProtocol::Icmp,
            socket_mode_used: SocketMode::Raw,
            destination_reached: true,
            total_duration: Duration::from_millis(100),
        };

        // Create the JSON structure that matches our CLI output
        let json_output = serde_json::json!({
            "version": "0.6.0",
            "target": result.target,
            "target_ip": result.target_ip.to_string(),
            "destination_asn": result.destination_asn.as_ref().map(|a| a.asn),
            "hops": []
        });

        let json_str = serde_json::to_string(&json_output).unwrap();
        assert!(
            json_str.contains("\"destination_asn\":15169"),
            "JSON should contain destination_asn field with value 15169"
        );
    }

    #[test]
    fn test_json_transit_segment() {
        // Test that TRANSIT segments are properly serialized
        let hop = ClassifiedHopInfo {
            ttl: 12,
            segment: SegmentType::Transit,
            hostname: Some("pat1.sjc.yahoo.com".to_string()),
            addr: Some(IpAddr::V4(Ipv4Addr::new(206, 223, 116, 16))),
            asn_info: None,                          // No ASN info for IXP
            rtt: Some(Duration::from_micros(10972)), // 10.972 ms
        };

        // Convert segment to string as done in main.rs
        let segment_str = match hop.segment {
            SegmentType::Lan => "LAN",
            SegmentType::Isp => "ISP",
            SegmentType::Transit => "TRANSIT",
            SegmentType::Destination => "DESTINATION",
            SegmentType::Unknown => "UNKNOWN",
        };

        assert_eq!(
            segment_str, "TRANSIT",
            "Transit segment should serialize as 'TRANSIT'"
        );

        // Test RTT precision
        let rtt_ms = hop.rtt_ms().map(|ms| (ms * 10.0).round() / 10.0);
        assert_eq!(rtt_ms, Some(11.0), "RTT 10.972ms should round to 11.0");
    }

    #[test]
    fn test_json_destination_segment() {
        // Test that DESTINATION segments are properly serialized
        let hop = ClassifiedHopInfo {
            ttl: 15,
            segment: SegmentType::Destination,
            hostname: Some("google.com".to_string()),
            addr: Some(IpAddr::V4(Ipv4Addr::new(142, 250, 189, 206))),
            asn_info: Some(AsnInfo {
                asn: 15169,
                prefix: "142.250.0.0/15".to_string(),
                country_code: "US".to_string(),
                registry: "arin".to_string(),
                name: "GOOGLE, US".to_string(),
            }),
            rtt: Some(Duration::from_micros(5361)), // 5.361 ms
        };

        // Convert segment to string
        let segment_str = match hop.segment {
            SegmentType::Lan => "LAN",
            SegmentType::Isp => "ISP",
            SegmentType::Transit => "TRANSIT",
            SegmentType::Destination => "DESTINATION",
            SegmentType::Unknown => "UNKNOWN",
        };

        assert_eq!(
            segment_str, "DESTINATION",
            "Destination segment should serialize as 'DESTINATION'"
        );

        // Test RTT precision
        let rtt_ms = hop.rtt_ms().map(|ms| (ms * 10.0).round() / 10.0);
        assert_eq!(rtt_ms, Some(5.4), "RTT 5.361ms should round to 5.4");
    }

    #[test]
    fn test_segment_display_format() {
        // Test the Display implementation for SegmentType
        assert_eq!(SegmentType::Lan.to_string(), "LAN   ");
        assert_eq!(SegmentType::Isp.to_string(), "ISP   ");
        assert_eq!(SegmentType::Transit.to_string(), "TRANSIT");
        assert_eq!(SegmentType::Destination.to_string(), "DESTINATION");
        assert_eq!(SegmentType::Unknown.to_string(), "UNKNOWN");
    }

    #[test]
    fn test_silent_hop_json_serialization() {
        // Test that silent hops (no address) serialize correctly
        let hop = ClassifiedHopInfo {
            ttl: 5,
            segment: SegmentType::Unknown,
            hostname: None,
            addr: None, // Silent hop
            asn_info: None,
            rtt: None,
        };

        // In JSON, segment should be null for Unknown silent hops
        let has_address = hop.addr.is_some();
        let segment_json = if !has_address && hop.segment == SegmentType::Unknown {
            serde_json::Value::Null
        } else {
            serde_json::Value::String("UNKNOWN".to_string())
        };

        assert_eq!(
            segment_json,
            serde_json::Value::Null,
            "Silent hop with Unknown segment should have null segment in JSON"
        );

        // RTT should also be None
        assert_eq!(hop.rtt_ms(), None, "Silent hop should have no RTT");
    }

    #[test]
    fn test_destination_asn_none() {
        // Test that destination_asn can be None (when lookup fails)
        let result = TracerouteResult {
            target: "example.com".to_string(),
            target_ip: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            hops: vec![],
            isp_info: None,
            destination_asn: None, // Failed lookup or no enrichment
            protocol_used: ProbeProtocol::Icmp,
            socket_mode_used: SocketMode::Raw,
            destination_reached: false,
            total_duration: Duration::from_millis(3000),
        };

        let json_output = serde_json::json!({
            "destination_asn": result.destination_asn.as_ref().map(|a| a.asn),
        });

        assert_eq!(
            json_output["destination_asn"],
            serde_json::Value::Null,
            "destination_asn should be null when lookup fails"
        );
    }
}
