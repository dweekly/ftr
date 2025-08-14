//! Example demonstrating proper error handling with ftr's structured errors
//!
//! Run with: cargo run --example error_handling

use ftr::{Ftr, ProbeProtocol, SocketMode, TracerouteConfigBuilder, TracerouteError};

#[tokio::main]
async fn main() {
    println!("ftr Error Handling Example\n");

    // Create an Ftr instance
    let ftr = Ftr::new();

    // Example 1: Handle permission errors gracefully
    println!("1. Testing permission handling:");
    let config = TracerouteConfigBuilder::new()
        .target("google.com")
        .socket_mode(SocketMode::Raw) // Requires root
        .build()
        .unwrap();

    match ftr.trace_with_config(config).await {
        Ok(result) => {
            println!("  Traceroute succeeded! Found {} hops", result.hop_count());
        }
        Err(TracerouteError::InsufficientPermissions {
            required,
            suggestion,
        }) => {
            println!("  Permission error detected!");
            println!("  - Required: {}", required);
            println!("  - Suggestion: {}", suggestion);
            println!("  - Action: Could retry with UDP mode or prompt for sudo");
        }
        Err(e) => {
            println!("  Other error: {}", e);
        }
    }

    // Example 2: Handle unimplemented features
    println!("\n2. Testing unimplemented feature handling:");
    let config = TracerouteConfigBuilder::new()
        .target("google.com")
        .protocol(ProbeProtocol::Tcp)
        .build()
        .unwrap();

    match ftr.trace_with_config(config).await {
        Ok(_) => println!("  Unexpected success!"),
        Err(TracerouteError::NotImplemented { feature }) => {
            println!("  Feature not implemented: {}", feature);
            println!("  - Action: Could fall back to ICMP or UDP protocol");
        }
        Err(e) => println!("  Other error: {}", e),
    }

    // Example 3: Handle IPv6 not supported
    println!("\n3. Testing IPv6 handling:");
    match ftr.trace("2001:4860:4860::8888").await {
        Ok(_) => println!("  Unexpected success!"),
        Err(TracerouteError::Ipv6NotSupported) => {
            println!("  IPv6 not supported yet");
            println!("  - Action: Could resolve to IPv4 or inform user");
        }
        Err(e) => println!("  Other error: {}", e),
    }

    // Example 4: Handle resolution errors
    println!("\n4. Testing DNS resolution error handling:");
    match ftr.trace("this-definitely-does-not-exist.invalid").await {
        Ok(_) => println!("  Unexpected success!"),
        Err(TracerouteError::ResolutionError(msg)) => {
            println!("  DNS resolution failed: {}", msg);
            println!("  - Action: Could suggest checking network or spelling");
        }
        Err(e) => println!("  Other error: {}", e),
    }

    // Example 5: Handle configuration errors
    println!("\n5. Testing configuration error handling:");
    let config_result = TracerouteConfigBuilder::new()
        .target("google.com")
        .start_ttl(10)
        .max_hops(5) // Invalid: max_hops < start_ttl
        .build();

    match config_result {
        Ok(_) => println!("  Unexpected success!"),
        Err(msg) => {
            println!("  Configuration error: {}", msg);
            println!("  - Action: Show validation rules to user");
        }
    }

    // Example 6: Programmatic fallback on errors
    println!("\n6. Demonstrating automatic fallback:");
    let target = "google.com";

    // Try different modes in order of preference
    let modes = vec![
        (SocketMode::Raw, "Raw socket (fastest)"),
        (SocketMode::Dgram, "ICMP datagram"),
        // UDP doesn't need a socket mode specification
    ];

    let mut success = false;
    for (mode, desc) in modes {
        println!("  Trying {}...", desc);
        let config = TracerouteConfigBuilder::new()
            .target(target)
            .socket_mode(mode)
            .max_hops(10)
            .build()
            .unwrap();

        match ftr.trace_with_config(config).await {
            Ok(result) => {
                println!(
                    "  ✓ Success with {}! Found {} hops",
                    desc,
                    result.hop_count()
                );
                success = true;
                break;
            }
            Err(TracerouteError::InsufficientPermissions { .. }) => {
                println!("  ✗ Insufficient permissions for {}", desc);
            }
            Err(e) => {
                println!("  ✗ Failed with {}: {}", desc, e);
            }
        }
    }

    if !success {
        println!("  Trying UDP mode (no special permissions)...");
        let config = TracerouteConfigBuilder::new()
            .target(target)
            .protocol(ProbeProtocol::Udp)
            .max_hops(10)
            .build()
            .unwrap();

        match ftr.trace_with_config(config).await {
            Ok(result) => {
                println!("  ✓ Success with UDP! Found {} hops", result.hop_count());
            }
            Err(e) => {
                println!("  ✗ All methods failed. Last error: {}", e);
            }
        }
    }

    println!("\nError handling example complete!");
}
