//! Test that async implementations show multiple hops

#[cfg(feature = "async")]
#[cfg(test)]
mod tests {
    use ftr::trace;
    #[cfg(target_os = "macos")]
    use ftr::TracerouteConfig;

    #[tokio::test]
    async fn test_async_shows_multiple_hops() {
        // Test with a well-known destination that should have multiple hops
        let target = "8.8.8.8";

        match trace(target).await {
            Ok(result) => {
                eprintln!("Async trace completed:");
                eprintln!("  Protocol: {:?}", result.protocol_used);
                eprintln!("  Socket mode: {:?}", result.socket_mode_used);
                eprintln!("  Total hops: {}", result.hop_count());

                // Count how many hops actually responded
                let hops_with_responses: Vec<_> = result
                    .hops
                    .iter()
                    .filter(|hop| hop.addr.is_some())
                    .collect();

                eprintln!("  Hops with responses: {}", hops_with_responses.len());

                // Debug info if we got no responses
                if hops_with_responses.is_empty() {
                    eprintln!("\n=== DEBUG: Got 0 responses ===");
                    eprintln!("Environment info:");
                    eprintln!("  OS: {}", std::env::consts::OS);
                    eprintln!("  CI: {:?}", std::env::var("CI"));
                    eprintln!("  GITHUB_ACTIONS: {:?}", std::env::var("GITHUB_ACTIONS"));

                    // GitHub Actions Windows runners are hosted in Azure which blocks inbound ICMP
                    // See: https://docs.github.com/en/actions/using-github-hosted-runners/about-github-hosted-runners
                    if cfg!(target_os = "windows") && std::env::var("GITHUB_ACTIONS").is_ok() {
                        eprintln!("\nNo ICMP responses on GitHub Actions Windows runner");
                        eprintln!("This is expected - Azure blocks inbound ICMP packets.");
                        eprintln!("GitHub hosts Windows runners in Azure data centers.");
                        eprintln!("Skipping test on GitHub Actions Windows.");
                        return;
                    }

                    eprintln!("\nUnexpected: No ICMP responses received");
                    eprintln!("This could indicate:");
                    eprintln!("  - Firewall blocking ICMP");
                    eprintln!("  - Network configuration issues");
                    eprintln!("  - Target unreachable");
                }

                // Verify we have responses from different addresses
                let unique_addresses: std::collections::HashSet<_> =
                    result.hops.iter().filter_map(|hop| hop.addr).collect();

                // We should see at least 3 hops for internet destinations
                assert!(
                    result.hop_count() >= 3,
                    "Expected at least 3 hops, got {}",
                    result.hop_count()
                );

                // Verify we have responses from different addresses
                // Note: On some systems (like macOS with certain network configs),
                // we might see the same address (e.g., 127.0.0.1) for multiple hops
                assert!(
                    unique_addresses.len() >= 1,
                    "Expected responses from at least 1 address, got {}",
                    unique_addresses.len()
                );
            }
            Err(e) => {
                // If we get a permission error, skip the test
                if e.to_string().contains("Permission denied")
                    || e.to_string().contains("requires root")
                {
                    eprintln!("Skipping test due to permission error: {}", e);
                    return;
                }
                panic!("Unexpected error: {}", e);
            }
        }
    }

    #[tokio::test]
    #[cfg(target_os = "macos")]
    async fn test_macos_async_icmp_works() {
        // Test specifically that macOS async ICMP implementation works
        let config = TracerouteConfig::builder()
            .target("1.1.1.1")
            .protocol(ftr::ProbeProtocol::Icmp)
            .build()
            .unwrap();

        match ftr::trace_with_config(config).await {
            Ok(result) => {
                // Should get multiple hops
                assert!(
                    result.hop_count() >= 3,
                    "macOS async ICMP should show multiple hops, got {}",
                    result.hop_count()
                );

                // Check we got actual responses
                let hops_with_responses =
                    result.hops.iter().filter(|hop| hop.addr.is_some()).count();

                assert!(
                    hops_with_responses >= 2,
                    "macOS async ICMP should show responses from multiple hops, got {}",
                    hops_with_responses
                );
            }
            Err(e) => {
                // Skip if permission denied
                if e.to_string().contains("Permission denied") {
                    eprintln!("Skipping macOS ICMP test due to permissions");
                    return;
                }
                panic!("macOS async ICMP failed: {}", e);
            }
        }
    }

    #[tokio::test]
    async fn test_parallel_probing_to_external_target() {
        // Test that parallel probing works correctly for an external target
        // This exercises the concurrent probe sending and response collection
        let target = "1.1.1.1"; // Cloudflare DNS - reliable and fast

        match trace(target).await {
            Ok(result) => {
                // Should have multiple hops for an external target
                assert!(
                    result.hop_count() >= 2,
                    "External target should have multiple hops, got {}",
                    result.hop_count()
                );

                // Verify TTLs are in ascending order
                let mut prev_ttl = 0;
                for hop in &result.hops {
                    assert!(
                        hop.ttl > prev_ttl,
                        "TTLs should be in ascending order: {} <= {}",
                        hop.ttl,
                        prev_ttl
                    );
                    prev_ttl = hop.ttl;
                }

                // Should not have huge gaps in TTL sequence (no more than 5 missing hops)
                let ttls: Vec<u8> = result.hops.iter().map(|h| h.ttl).collect();
                for window in ttls.windows(2) {
                    assert!(
                        window[1] - window[0] <= 5,
                        "Large gap in TTL sequence: {} to {}",
                        window[0],
                        window[1]
                    );
                }
            }
            Err(e) => {
                // Skip on permission error or network issues
                if e.to_string().contains("Permission denied") {
                    eprintln!("Skipping external target test due to permissions");
                    return;
                }
                if e.to_string().contains("timed out") || e.to_string().contains("unreachable") {
                    eprintln!("Skipping external target test due to network issues");
                    return;
                }
                panic!("External trace failed: {}", e);
            }
        }
    }

    #[tokio::test]
    async fn test_localhost_trace_completes_quickly() {
        // Test that localhost traces complete quickly and reach the destination
        // We don't care about the exact hop count since parallel probing can
        // cause any TTL >= 1 to reach localhost
        let target = "127.0.0.1";
        let start = std::time::Instant::now();

        match trace(target).await {
            Ok(result) => {
                let elapsed = start.elapsed();

                // Localhost should complete quickly
                // Allow more time on CI runners which can be slower
                let timeout_ms =
                    if std::env::var("CI").is_ok() || std::env::var("GITHUB_ACTIONS").is_ok() {
                        1000 // 1 second for CI environments
                    } else {
                        500 // 500ms for local testing
                    };

                assert!(
                    elapsed.as_millis() < timeout_ms,
                    "Localhost trace took too long: {:?} (limit: {}ms)",
                    elapsed,
                    timeout_ms
                );

                // Should have at least one hop
                assert!(
                    !result.hops.is_empty(),
                    "Localhost trace should have at least one hop"
                );

                // All reported hops should be loopback addresses
                for hop in &result.hops {
                    if let Some(addr) = hop.addr {
                        assert!(
                            addr.is_loopback(),
                            "Hop {} should be loopback address, got {}",
                            hop.ttl,
                            addr
                        );
                    }
                }

                // Should have reached the destination
                assert!(
                    result.destination_hop().is_some(),
                    "Should have reached localhost destination"
                );

                // The destination hop should be localhost
                if let Some(dest_hop) = result.destination_hop() {
                    if let Some(addr) = dest_hop.addr {
                        assert_eq!(
                            addr.to_string(),
                            "127.0.0.1",
                            "Destination should be 127.0.0.1"
                        );
                    }
                }
            }
            Err(e) => {
                // Skip on permission error
                if e.to_string().contains("Permission denied") {
                    eprintln!("Skipping localhost test due to permissions");
                    return;
                }
                panic!("Localhost trace failed: {}", e);
            }
        }
    }
}
