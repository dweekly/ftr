//! Tests for structured error handling in the ftr library
//!
//! These tests verify that the library returns proper structured errors
//! that are easy for developers to handle programmatically.

#[cfg(target_os = "linux")]
use ftr::SocketMode;
use ftr::{ConfigError, ProbeProtocol, TracerouteConfigBuilder, TracerouteError};

#[tokio::test]
async fn test_insufficient_permissions_error() {
    // Only run this test if we're not root and on Linux
    // macOS doesn't require root for DGRAM ICMP sockets
    #[cfg(target_os = "linux")]
    {
        // Try to create a raw socket without root - should get structured error
        let config = TracerouteConfigBuilder::new()
            .target("127.0.0.1")
            .socket_mode(SocketMode::Raw)
            .build()
            .expect("failed to build traceroute config");

        if !ftr::socket::utils::is_root() {
            let ftr_instance = ftr::Ftr::new();
            let result = ftr_instance.trace_with_config(config).await;

            let err = result.expect_err("Expected permission error but operation succeeded");
            assert!(
                matches!(err, TracerouteError::InsufficientPermissions { .. }),
                "Expected InsufficientPermissions error, got: {:?}",
                err
            );
            if let TracerouteError::InsufficientPermissions {
                required,
                suggestion,
            } = err
            {
                // Good! We got a structured error
                assert!(required.contains("root") || required.contains("CAP_NET_RAW"));
                assert!(!suggestion.is_empty());
                println!("Got expected structured error:");
                println!("  Required: {}", required);
                println!("  Suggestion: {}", suggestion);
            }
        }
    }

    // On non-Linux platforms, just check that the test compiles and can run
    #[cfg(not(target_os = "linux"))]
    {
        println!("Skipping permission test on non-Linux platform");
    }
}

#[tokio::test]
async fn test_tcp_not_implemented_error() {
    let config = TracerouteConfigBuilder::new()
        .target("127.0.0.1")
        .protocol(ProbeProtocol::Tcp)
        .build()
        .expect("failed to build traceroute config");

    let ftr_instance = ftr::Ftr::new();
    let result = ftr_instance.trace_with_config(config).await;

    let err = result.expect_err("Expected NotImplemented error but operation succeeded");
    assert!(
        matches!(&err, TracerouteError::NotImplemented { feature } if feature == "TCP traceroute"),
        "Expected NotImplemented error for TCP traceroute, got: {:?}",
        err
    );
    println!("Got expected NotImplemented error for TCP traceroute");
}

#[tokio::test]
async fn test_ipv6_target_platform_behavior() {
    let config = TracerouteConfigBuilder::new()
        .target("::1") // IPv6 localhost
        .build()
        .expect("failed to build traceroute config");

    let ftr_instance = ftr::Ftr::new();
    let result = ftr_instance.trace_with_config(config).await;

    // macOS (unprivileged DGRAM ICMPv6) and Linux (unprivileged UDP with
    // IPV6_RECVERR) both trace IPv6 without root: a loopback trace reaches
    // ::1 in one hop, classified as LAN. Platforms without IPv6 probe
    // support must surface the typed Ipv6NotSupported error.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        let trace = result.expect("IPv6 loopback trace should succeed unprivileged");
        assert!(trace.destination_reached, "::1 must be reachable");
        assert_eq!(
            trace.hops.first().and_then(|h| h.addr),
            Some("::1".parse().expect("valid IPv6")),
        );
        println!("IPv6 loopback trace succeeded");
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        assert!(
            matches!(&result, Err(TracerouteError::Ipv6NotSupported)),
            "Expected Ipv6NotSupported error, got: {:?}",
            result
        );
        println!("Got expected Ipv6NotSupported error");
    }
}

#[tokio::test]
async fn test_resolution_error() {
    let config = TracerouteConfigBuilder::new()
        .target("this-is-definitely-not-a-valid-hostname-12345.invalid")
        .build()
        .expect("failed to build traceroute config");

    let ftr_instance = ftr::Ftr::new();
    let result = ftr_instance.trace_with_config(config).await;

    let err = result.expect_err("Expected resolution error but operation succeeded");
    match err {
        TracerouteError::ResolutionError(msg) => {
            // Good! We got a structured error
            println!("Got expected ResolutionError: {}", msg);
            // Just check that we got a non-empty error message
            assert!(!msg.is_empty());
        }
        e => {
            // Could also be a socket error if DNS resolution somehow succeeded
            println!("Got different error (might be OK): {:?}", e);
        }
    }
}

#[tokio::test]
async fn test_config_validation_errors() {
    // Test invalid start TTL
    let result = TracerouteConfigBuilder::new()
        .target("127.0.0.1")
        .start_ttl(0)
        .build();

    assert!(result.is_err());
    assert_eq!(
        result.expect_err("start_ttl(0) must fail validation"),
        ConfigError::InvalidStartTtl
    );

    // Test max_hops < start_ttl
    let result = TracerouteConfigBuilder::new()
        .target("127.0.0.1")
        .start_ttl(10)
        .max_hops(5)
        .build();

    assert!(result.is_err());
    assert_eq!(
        result.expect_err("max_hops < start_ttl must fail validation"),
        ConfigError::MaxHopsLessThanStartTtl {
            start_ttl: 10,
            max_hops: 5,
        }
    );

    // Test empty target
    let result = TracerouteConfigBuilder::new().target("").build();

    assert!(result.is_err());

    // When passed through trace_with_config, should become TracerouteError::ConfigError
    let config = TracerouteConfigBuilder::new().target("").build();
    assert!(config.is_err(), "Expected config validation to fail");

    let ftr_instance = ftr::Ftr::new();
    let result = ftr_instance.trace("").await;
    assert!(
        matches!(&result, Err(TracerouteError::ConfigError(_))),
        "Expected ConfigError, got: {:?}",
        result
    );
}

#[tokio::test]
async fn test_error_display_formatting() {
    // Test that errors have good display formatting
    let errors: Vec<TracerouteError> = vec![
        TracerouteError::InsufficientPermissions {
            required: "root or CAP_NET_RAW capability".to_string(),
            suggestion: "Try running with sudo or use UDP mode with --udp flag".to_string(),
        },
        TracerouteError::NotImplemented {
            feature: "TCP traceroute".to_string(),
        },
        TracerouteError::Ipv6NotSupported,
        TracerouteError::ResolutionError("Failed to resolve host: example.com".to_string()),
        TracerouteError::SocketError("Failed to create socket: Permission denied".to_string()),
        TracerouteError::ConfigError(ConfigError::InvalidStartTtl),
        TracerouteError::ProbeSendError("Failed to send probe: Network unreachable".to_string()),
    ];

    for error in errors {
        let display = format!("{}", error);
        println!("Error display: {}", display);

        // All errors should have non-empty display strings
        assert!(!display.is_empty());

        // Check that structured fields are included in display
        match &error {
            TracerouteError::InsufficientPermissions { required, .. } => {
                assert!(display.contains(required));
            }
            TracerouteError::NotImplemented { feature } => {
                assert!(display.contains(feature));
            }
            _ => {}
        }
    }
}
