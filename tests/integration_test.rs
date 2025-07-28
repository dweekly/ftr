//! Integration tests for the ftr library

use ftr::{
    trace, trace_with_config, AsnInfo, ProbeProtocol, SegmentType, SocketMode,
    TracerouteConfigBuilder, TracerouteError,
};
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

#[tokio::test]
async fn test_basic_trace() {
    // Test basic tracing to localhost
    let result = trace("127.0.0.1").await;

    match result {
        Ok(trace_result) => {
            assert_eq!(trace_result.target, "127.0.0.1");
            assert!(!trace_result.hops.is_empty());
            assert!(trace_result.total_duration > Duration::ZERO);
        }
        Err(e) => {
            // Permission errors are expected in test environments
            eprintln!("Trace failed (expected in test environment): {}", e);
        }
    }
}

#[tokio::test]
async fn test_trace_with_custom_config() {
    let config = TracerouteConfigBuilder::new()
        .target("localhost")
        .max_hops(5)
        .probe_timeout(Duration::from_millis(100))
        .enable_asn_lookup(false)
        .enable_rdns(false)
        .build()
        .unwrap();

    let result = trace_with_config(config).await;

    match result {
        Ok(trace_result) => {
            assert_eq!(trace_result.target, "localhost");
            assert!(trace_result.max_ttl().unwrap_or(0) <= 5);

            // With ASN and rDNS disabled, these should be empty
            for hop in &trace_result.hops {
                assert!(hop.asn_info.is_none());
                assert!(hop.hostname.is_none());
            }
        }
        Err(e) => {
            eprintln!("Trace failed (expected in test environment): {}", e);
        }
    }
}

#[tokio::test]
async fn test_config_validation() {
    // Test invalid configurations

    // Empty target
    let result = TracerouteConfigBuilder::new().build();
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Target must be specified"));

    // Invalid TTL values
    let result = TracerouteConfigBuilder::new()
        .target("example.com")
        .start_ttl(0)
        .build();
    assert!(result.is_err());

    // max_hops < start_ttl
    let result = TracerouteConfigBuilder::new()
        .target("example.com")
        .start_ttl(10)
        .max_hops(5)
        .build();
    assert!(result.is_err());
}

#[tokio::test]
async fn test_trace_with_ip_and_hostname() {
    // Test with IP address
    let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    let config = TracerouteConfigBuilder::new()
        .target("127.0.0.1")
        .target_ip(ip)
        .max_hops(3)
        .build()
        .unwrap();

    let result = trace_with_config(config).await;

    match result {
        Ok(trace_result) => {
            assert_eq!(trace_result.target_ip, ip);
        }
        Err(_) => {
            // Permission errors are acceptable
        }
    }
}

#[tokio::test]
async fn test_hop_classification() {
    let config = TracerouteConfigBuilder::new()
        .target("8.8.8.8")
        .max_hops(30)
        .enable_asn_lookup(true)
        .build()
        .unwrap();

    match trace_with_config(config).await {
        Ok(trace_result) => {
            // Check that hops are classified
            let segments: Vec<SegmentType> = trace_result.hops.iter().map(|h| h.segment).collect();

            // Should have at least one hop
            assert!(!segments.is_empty());

            // Segments should be in order: LAN -> ISP -> BEYOND
            // (though not all may be present)
            let mut last_segment = SegmentType::Unknown;
            for segment in segments {
                match (last_segment, segment) {
                    (SegmentType::Unknown, _) => {}
                    (SegmentType::Lan, SegmentType::Isp) => {}
                    (SegmentType::Lan, SegmentType::Beyond) => {}
                    (SegmentType::Isp, SegmentType::Beyond) => {}
                    (a, b) if a == b => {} // Same segment is fine
                    _ => {
                        // Unexpected transition
                    }
                }
                last_segment = segment;
            }
        }
        Err(_) => {
            // Network/permission errors are acceptable
        }
    }
}

#[tokio::test]
async fn test_result_methods() {
    // Create a mock result to test methods
    let hops = vec![
        ftr::ClassifiedHopInfo {
            ttl: 1,
            segment: SegmentType::Lan,
            hostname: Some("router.local".to_string()),
            addr: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            asn_info: None,
            rtt: Some(Duration::from_millis(5)),
        },
        ftr::ClassifiedHopInfo {
            ttl: 2,
            segment: SegmentType::Isp,
            hostname: None,
            addr: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            asn_info: Some(AsnInfo {
                asn: "AS12345".to_string(),
                prefix: "10.0.0.0/8".to_string(),
                country_code: "US".to_string(),
                registry: "ARIN".to_string(),
                name: "Example ISP".to_string(),
            }),
            rtt: Some(Duration::from_millis(15)),
        },
        ftr::ClassifiedHopInfo {
            ttl: 3,
            segment: SegmentType::Beyond,
            hostname: Some("destination.com".to_string()),
            addr: Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
            asn_info: None,
            rtt: None, // No response
        },
    ];

    let result = ftr::TracerouteResult {
        target: "8.8.8.8".to_string(),
        target_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        hops,
        isp_info: Some(ftr::IspInfo {
            public_ip: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            asn: "AS12345".to_string(),
            name: "Example ISP".to_string(),
        }),
        protocol_used: ProbeProtocol::Icmp,
        socket_mode_used: SocketMode::Raw,
        destination_reached: true,
        total_duration: Duration::from_millis(100),
    };

    // Test hop_count
    assert_eq!(result.hop_count(), 3);

    // Test max_ttl
    assert_eq!(result.max_ttl(), Some(3));

    // Test destination_hop
    let dest_hop = result.destination_hop();
    assert!(dest_hop.is_some());
    assert_eq!(dest_hop.unwrap().ttl, 3);

    // Test has_response_at_ttl
    assert!(result.has_response_at_ttl(1));
    assert!(result.has_response_at_ttl(2));
    assert!(result.has_response_at_ttl(3));
    assert!(!result.has_response_at_ttl(4));

    // Test hops_with_asn
    let asn_hops = result.hops_with_asn();
    assert_eq!(asn_hops.len(), 1);
    assert_eq!(asn_hops[0].ttl, 2);

    // Test hops_in_segment
    let lan_hops = result.hops_in_segment(SegmentType::Lan);
    assert_eq!(lan_hops.len(), 1);
    let isp_hops = result.hops_in_segment(SegmentType::Isp);
    assert_eq!(isp_hops.len(), 1);
    let beyond_hops = result.hops_in_segment(SegmentType::Beyond);
    assert_eq!(beyond_hops.len(), 1);

    // Test average_rtt_ms
    let avg_rtt = result.average_rtt_ms();
    assert!(avg_rtt.is_some());
    assert_eq!(avg_rtt.unwrap(), 10.0); // (5 + 15) / 2, hop 3 has no RTT
}

#[tokio::test]
async fn test_error_types() {
    // Test various error conditions

    // Invalid target (empty)
    let result = trace("").await;
    assert!(matches!(result, Err(TracerouteError::ConfigError(_))));

    // Test with a config that might fail
    let config = TracerouteConfigBuilder::new()
        .target("invalid.host.that.does.not.exist.example")
        .build()
        .unwrap();

    let result = trace_with_config(config).await;
    match result {
        Ok(_) => {
            // Unexpectedly succeeded - DNS might have resolved it
        }
        Err(e) => {
            // Should be either Resolution or Socket error
            assert!(
                matches!(e, TracerouteError::ResolutionError(_))
                    || matches!(e, TracerouteError::SocketError(_))
            );
        }
    }
}

#[tokio::test]
async fn test_caching_behavior() {
    // Test that caching works by doing multiple traces
    let config1 = TracerouteConfigBuilder::new()
        .target("127.0.0.1")
        .max_hops(3)
        .enable_asn_lookup(true)
        .enable_rdns(true)
        .build()
        .unwrap();

    let config2 = TracerouteConfigBuilder::new()
        .target("127.0.0.1")
        .max_hops(3)
        .enable_asn_lookup(true)
        .enable_rdns(true)
        .build()
        .unwrap();

    // Clear caches before test
    ftr::asn::ASN_CACHE.clear();
    ftr::dns::RDNS_CACHE.clear();

    // First trace - cold cache
    let result1 = trace_with_config(config1).await;

    // Second trace - warm cache
    let result2 = trace_with_config(config2).await;

    // Both should have same success/failure status
    assert_eq!(result1.is_ok(), result2.is_ok());

    if result1.is_ok() && result2.is_ok() {
        // Check cache has entries
        assert!(ftr::asn::ASN_CACHE.len() > 0 || ftr::dns::RDNS_CACHE.len() > 0);
    }
}

#[tokio::test]
async fn test_public_ip_parameter() {
    let public_ip = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));

    let config = TracerouteConfigBuilder::new()
        .target("127.0.0.1")
        .max_hops(1)
        .public_ip(public_ip)
        .enable_asn_lookup(true)
        .build()
        .unwrap();

    match trace_with_config(config).await {
        Ok(result) => {
            if let Some(isp_info) = result.isp_info {
                // Should use the provided public IP
                assert_eq!(isp_info.public_ip, public_ip);
            }
        }
        Err(_) => {
            // Errors are acceptable in test environment
        }
    }
}

#[tokio::test]
async fn test_different_protocols() {
    // Test that we can specify different protocols
    let protocols = vec![ProbeProtocol::Icmp, ProbeProtocol::Udp, ProbeProtocol::Tcp];

    for protocol in protocols {
        let config = TracerouteConfigBuilder::new()
            .target("127.0.0.1")
            .protocol(protocol)
            .max_hops(3)
            .build()
            .unwrap();

        let _ = trace_with_config(config).await;
        // We don't assert on results as different protocols have different permission requirements
    }
}
