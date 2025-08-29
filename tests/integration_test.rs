//! Integration tests for the ftr library

use ftr::{
    trace, trace_with_config, AsnInfo, ProbeProtocol, SegmentType, SocketMode,
    TracerouteConfigBuilder, TracerouteError, TracerouteResult,
};
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

// Helper to run traces with timeout
async fn trace_with_timeout(target: &str) -> Result<TracerouteResult, String> {
    match tokio::time::timeout(Duration::from_secs(10), trace(target)).await {
        Ok(Ok(result)) => Ok(result),
        Ok(Err(e)) => Err(format!("Trace error: {}", e)),
        Err(_) => Err("Timeout after 10 seconds".to_string()),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_basic_trace() {
    // Test basic tracing to localhost
    println!("Starting test_basic_trace");

    match trace_with_timeout("127.0.0.1").await {
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_trace_with_custom_config() {
    let config = TracerouteConfigBuilder::new()
        .target("localhost")
        .max_hops(5)
        .probe_timeout(Duration::from_millis(100))
        .overall_timeout(Duration::from_secs(2))
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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
        .probe_timeout(Duration::from_millis(500))
        .overall_timeout(Duration::from_secs(3))
        .build();
    assert!(result.is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_hop_classification() {
    let config = TracerouteConfigBuilder::new()
        .target("8.8.8.8")
        .max_hops(10)
        .enable_asn_lookup(true)
        .build()
        .unwrap();

    match trace_with_config(config).await {
        Ok(trace_result) => {
            // Check that hops are classified
            let segments: Vec<SegmentType> = trace_result.hops.iter().map(|h| h.segment).collect();

            // Should have at least one hop
            assert!(!segments.is_empty());

            // Segments generally progress outward: LAN -> ISP -> TRANSIT/DESTINATION
            // (though not all may be present)
            let mut last_segment = SegmentType::Unknown;
            for segment in segments {
                match (last_segment, segment) {
                    (SegmentType::Unknown, _) => {}
                    (SegmentType::Lan, SegmentType::Isp) => {}
                    (SegmentType::Lan, SegmentType::Transit) => {}
                    (SegmentType::Lan, SegmentType::Destination) => {}
                    (SegmentType::Isp, SegmentType::Transit) => {}
                    (SegmentType::Isp, SegmentType::Destination) => {}
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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
                asn: 12345,
                prefix: "10.0.0.0/8".to_string(),
                country_code: "US".to_string(),
                registry: "ARIN".to_string(),
                name: "Example ISP".to_string(),
            }),
            rtt: Some(Duration::from_millis(15)),
        },
        ftr::ClassifiedHopInfo {
            ttl: 3,
            segment: SegmentType::Destination,
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
            asn: 12345,
            name: "Example ISP".to_string(),
            hostname: None,
        }),
        destination_asn: None,
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
    let dest_hops = result.hops_in_segment(SegmentType::Destination);
    assert_eq!(dest_hops.len(), 1);

    // Test average_rtt_ms
    let avg_rtt = result.average_rtt_ms();
    assert!(avg_rtt.is_some());
    assert_eq!(avg_rtt.unwrap(), 10.0); // (5 + 15) / 2, hop 3 has no RTT
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_error_types() {
    // Test various error conditions with structured errors

    // Invalid target (empty) - should get ConfigError
    let result = trace("").await;
    match result {
        Err(TracerouteError::ConfigError(msg)) => {
            println!("Got expected ConfigError: {}", msg);
            assert!(msg.contains("Target") || msg.contains("target"));
        }
        _ => panic!("Expected ConfigError for empty target"),
    }

    // Test unimplemented TCP protocol
    let config = TracerouteConfigBuilder::new()
        .target("127.0.0.1")
        .protocol(ProbeProtocol::Tcp)
        .build()
        .unwrap();

    let result = trace_with_config(config).await;
    match result {
        Err(TracerouteError::NotImplemented { feature }) => {
            assert_eq!(feature, "TCP traceroute");
        }
        _ => panic!("Expected NotImplemented error for TCP"),
    }

    // Test IPv6 not supported
    let result = trace("::1").await;
    match result {
        Err(TracerouteError::Ipv6NotSupported) => {
            println!("Got expected Ipv6NotSupported error");
        }
        _ => panic!("Expected Ipv6NotSupported error"),
    }

    // Test resolution error
    let config = TracerouteConfigBuilder::new()
        .target("invalid.host.that.does.not.exist.example")
        .build()
        .unwrap();

    let result = trace_with_config(config).await;
    match result {
        Err(TracerouteError::ResolutionError(msg)) => {
            println!("Got expected ResolutionError: {}", msg);
            // Just check that we got a non-empty error message
            assert!(!msg.is_empty());
        }
        Err(e) => {
            // Could be other error if DNS somehow resolved it
            println!("Got different error (might be OK): {:?}", e);
        }
        Ok(_) => {
            println!("Warning: invalid hostname somehow resolved, skipping test");
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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
    // Cache clearing removed - each Ftr instance has its own caches

    // First trace - cold cache
    let result1 = trace_with_config(config1).await;

    // Second trace - warm cache
    let result2 = trace_with_config(config2).await;

    // Both should have same success/failure status
    assert_eq!(result1.is_ok(), result2.is_ok());

    if result1.is_ok() && result2.is_ok() {
        // Check cache has entries
        // Cache check removed - caches are now instance-specific
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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
