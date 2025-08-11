//! Tests for structured error handling in the ftr library
//!
//! These tests verify that the library returns proper structured errors
//! that are easy for developers to handle programmatically.

use ftr::{ProbeProtocol, SocketMode, TracerouteConfigBuilder, TracerouteError};

#[tokio::test]
async fn test_insufficient_permissions_error() {
    // Try to create a raw socket without root - should get structured error
    let config = TracerouteConfigBuilder::new()
        .target("127.0.0.1")
        .socket_mode(SocketMode::Raw)
        .build()
        .unwrap();

    // Only run this test if we're not root
    if !is_root() {
        let result = ftr::trace_with_config(config).await;

        match result {
            Err(TracerouteError::InsufficientPermissions {
                required,
                suggestion,
            }) => {
                // Good! We got a structured error
                assert!(required.contains("root") || required.contains("CAP_NET_RAW"));
                assert!(!suggestion.is_empty());
                println!("Got expected structured error:");
                println!("  Required: {}", required);
                println!("  Suggestion: {}", suggestion);
            }
            Err(e) => {
                panic!("Expected InsufficientPermissions error, got: {:?}", e);
            }
            Ok(_) => {
                panic!("Expected permission error but operation succeeded");
            }
        }
    }
}

#[tokio::test]
async fn test_tcp_not_implemented_error() {
    let config = TracerouteConfigBuilder::new()
        .target("127.0.0.1")
        .protocol(ProbeProtocol::Tcp)
        .build()
        .unwrap();

    let result = ftr::trace_with_config(config).await;

    match result {
        Err(TracerouteError::NotImplemented { feature }) => {
            // Good! We got a structured error
            assert_eq!(feature, "TCP traceroute");
            println!("Got expected NotImplemented error for: {}", feature);
        }
        Err(e) => {
            panic!("Expected NotImplemented error, got: {:?}", e);
        }
        Ok(_) => {
            panic!("Expected NotImplemented error but operation succeeded");
        }
    }
}

#[tokio::test]
async fn test_ipv6_not_supported_error() {
    let config = TracerouteConfigBuilder::new()
        .target("::1") // IPv6 localhost
        .build()
        .unwrap();

    let result = ftr::trace_with_config(config).await;

    match result {
        Err(TracerouteError::Ipv6NotSupported) => {
            // Good! We got a structured error
            println!("Got expected Ipv6NotSupported error");
        }
        Err(e) => {
            panic!("Expected Ipv6NotSupported error, got: {:?}", e);
        }
        Ok(_) => {
            panic!("Expected Ipv6NotSupported error but operation succeeded");
        }
    }
}

#[tokio::test]
async fn test_resolution_error() {
    let config = TracerouteConfigBuilder::new()
        .target("this-is-definitely-not-a-valid-hostname-12345.invalid")
        .build()
        .unwrap();

    let result = ftr::trace_with_config(config).await;

    match result {
        Err(TracerouteError::ResolutionError(msg)) => {
            // Good! We got a structured error
            println!("Got expected ResolutionError: {}", msg);
            // Just check that we got a non-empty error message
            assert!(!msg.is_empty());
        }
        Err(e) => {
            // Could also be a socket error if DNS resolution somehow succeeded
            println!("Got different error (might be OK): {:?}", e);
        }
        Ok(_) => {
            panic!("Expected resolution error but operation succeeded");
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
    assert!(result.unwrap_err().contains("start_ttl must be at least 1"));

    // Test max_hops < start_ttl
    let result = TracerouteConfigBuilder::new()
        .target("127.0.0.1")
        .start_ttl(10)
        .max_hops(5)
        .build();

    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .contains("max_hops must be greater than or equal to start_ttl"));

    // Test empty target
    let result = TracerouteConfigBuilder::new().target("").build();

    assert!(result.is_err());

    // When passed through trace_with_config, should become TracerouteError::ConfigError
    let config = TracerouteConfigBuilder::new().target("").build();

    match config {
        Err(_msg) => {
            let result = ftr::trace(&"").await;
            match result {
                Err(TracerouteError::ConfigError(e)) => {
                    println!("Got expected ConfigError: {}", e);
                }
                _ => panic!("Expected ConfigError"),
            }
        }
        Ok(_) => panic!("Expected config validation to fail"),
    }
}

// Helper function to check if running as root
fn is_root() -> bool {
    // Use the helper from utils module
    ftr::socket::utils::is_root()
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
        TracerouteError::ConfigError(
            "Invalid configuration: start_ttl must be at least 1".to_string(),
        ),
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
