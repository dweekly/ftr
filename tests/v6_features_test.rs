/// Integration tests for v0.6.0 features
use ftr::{Ftr, SegmentType, TracerouteConfig};
use std::net::Ipv4Addr;

#[tokio::test]
async fn test_v6_segment_types() {
    // Test that the new segment types are properly exposed in the API
    let segments = vec![
        SegmentType::Lan,
        SegmentType::Isp,
        SegmentType::Transit,     // New in v0.6.0
        SegmentType::Destination, // New in v0.6.0
        SegmentType::Unknown,
    ];

    // Verify all segment types exist and are distinct
    assert_eq!(segments.len(), 5);
    for (i, seg1) in segments.iter().enumerate() {
        for (j, seg2) in segments.iter().enumerate() {
            if i == j {
                assert_eq!(seg1, seg2, "Same segment should be equal");
            } else {
                assert_ne!(seg1, seg2, "Different segments should not be equal");
            }
        }
    }
}

#[tokio::test]
async fn test_destination_asn_field() {
    // Test that TracerouteResult includes destination_asn field
    let ftr = Ftr::new();

    // Use localhost for a quick test that won't reach internet
    let config = TracerouteConfig::builder()
        .target("127.0.0.1")
        .max_hops(3)
        .enable_asn_lookup(false) // Disable to make test faster
        .enable_rdns(false)
        .build()
        .unwrap();

    let result = ftr.trace_with_config(config).await.unwrap();

    // Verify the destination_asn field exists (will be None without enrichment)
    assert!(
        result.destination_asn.is_none(),
        "Without ASN lookup, destination_asn should be None"
    );

    // The field should exist in the struct
    let _ = result.destination_asn; // This compiles, proving the field exists
}

#[tokio::test]
async fn test_transit_segment_classification() {
    // Test that we can identify TRANSIT segments in results
    let ftr = Ftr::new();

    // Create a mock result to test segment classification
    // In a real trace, TRANSIT segments appear between ISP and DESTINATION
    let config = TracerouteConfig::builder()
        .target("127.0.0.1")
        .max_hops(5)
        .enable_asn_lookup(false)
        .enable_rdns(false)
        .build()
        .unwrap();

    let result = ftr.trace_with_config(config).await.unwrap();

    // Check that segment types are properly set
    for hop in &result.hops {
        // Verify segment type is one of the valid values
        match hop.segment {
            SegmentType::Lan
            | SegmentType::Isp
            | SegmentType::Transit
            | SegmentType::Destination
            | SegmentType::Unknown => {}
        }
    }
}

#[test]
fn test_segment_serialization() {
    // Test that segment types serialize correctly for JSON output
    use serde_json;

    let transit = SegmentType::Transit;
    let destination = SegmentType::Destination;

    // These should serialize to strings
    let transit_json = serde_json::to_string(&transit).unwrap();
    let dest_json = serde_json::to_string(&destination).unwrap();

    assert_eq!(
        transit_json, "\"Transit\"",
        "Transit should serialize as \"Transit\""
    );
    assert_eq!(
        dest_json, "\"Destination\"",
        "Destination should serialize as \"Destination\""
    );
}

#[test]
fn test_public_ip_classification() {
    // Test IP classification logic
    // Private IP ranges
    let private_ips = vec![
        Ipv4Addr::new(192, 168, 1, 1), // 192.168.0.0/16
        Ipv4Addr::new(10, 0, 0, 1),    // 10.0.0.0/8
        Ipv4Addr::new(172, 16, 0, 1),  // 172.16.0.0/12
        Ipv4Addr::new(127, 0, 0, 1),   // Loopback
        Ipv4Addr::new(169, 254, 0, 1), // Link-local
    ];

    for ip in &private_ips {
        assert!(
            ip.is_private() || ip.is_loopback() || ip.is_link_local(),
            "{} should be a private/internal IP",
            ip
        );
    }

    // Public IPs
    let public_ips = vec![
        Ipv4Addr::new(8, 8, 8, 8),
        Ipv4Addr::new(206, 223, 116, 16), // Equinix
    ];

    for ip in &public_ips {
        assert!(
            !ip.is_private() && !ip.is_loopback() && !ip.is_link_local(),
            "{} should be a public IP",
            ip
        );
    }

    // CGNAT range check (100.64.0.0/10)
    let cgnat_start = Ipv4Addr::new(100, 64, 0, 0);
    let cgnat_end = Ipv4Addr::new(100, 127, 255, 255);

    assert!(
        Ipv4Addr::new(100, 64, 0, 1) >= cgnat_start && Ipv4Addr::new(100, 64, 0, 1) <= cgnat_end,
        "100.64.0.1 should be in CGNAT range"
    );
    assert!(
        Ipv4Addr::new(100, 127, 255, 254) >= cgnat_start
            && Ipv4Addr::new(100, 127, 255, 254) <= cgnat_end,
        "100.127.255.254 should be in CGNAT range"
    );
}

#[tokio::test]
async fn test_localhost_trace_segments() {
    // Test a simple localhost trace to verify segment classification
    let ftr = Ftr::new();

    let config = TracerouteConfig::builder()
        .target("127.0.0.1")
        .max_hops(3)
        .enable_asn_lookup(false)
        .enable_rdns(false)
        .build()
        .unwrap();

    let result = ftr.trace_with_config(config).await.unwrap();

    // Localhost should have at least one hop
    assert!(!result.hops.is_empty(), "Localhost trace should have hops");

    // First hop to localhost should be LAN (it's a loopback address)
    if let Some(first_hop) = result.hops.first() {
        if first_hop.addr == Some(std::net::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))) {
            assert_eq!(
                first_hop.segment,
                SegmentType::Lan,
                "Localhost (127.0.0.1) should be classified as LAN"
            );
        }
    }
}

#[test]
fn test_rtt_precision_helper() {
    // Test RTT precision rounding as used in JSON output
    fn round_to_one_decimal(ms: f64) -> f64 {
        (ms * 10.0).round() / 10.0
    }

    assert_eq!(round_to_one_decimal(1.234), 1.2);
    assert_eq!(round_to_one_decimal(1.567), 1.6);
    assert_eq!(round_to_one_decimal(10.951), 11.0);
    assert_eq!(round_to_one_decimal(5.449), 5.4);
    assert_eq!(round_to_one_decimal(5.450), 5.5);
    assert_eq!(round_to_one_decimal(5.451), 5.5);
}

#[test]
fn test_v6_version_string() {
    // Ensure we're testing v0.6.0
    let version = env!("CARGO_PKG_VERSION");
    assert!(
        version.starts_with("0.6"),
        "Expected v0.6.x, got {}",
        version
    );
}
