//! Test that async implementations show multiple hops

#[cfg(feature = "async")]
#[cfg(test)]
mod tests {
    use ftr::{trace, TracerouteConfig};

    #[tokio::test]
    #[cfg_attr(not(any(target_os = "linux", target_os = "macos")), ignore)]
    async fn test_async_shows_multiple_hops() {
        // Test with a well-known destination that should have multiple hops
        let target = "8.8.8.8";

        match trace(target).await {
            Ok(result) => {
                // Debug: print what we got
                eprintln!("Got {} hops", result.hop_count());
                for (i, hop) in result.hops.iter().enumerate() {
                    if let Some(addr) = hop.addr {
                        eprintln!("  Hop {}: {}", i + 1, addr);
                    }
                }

                // Special case: if all responses are from localhost, it might be a test
                // environment issue (e.g., running in a container or sandbox)
                let unique_addresses: std::collections::HashSet<_> =
                    result.hops.iter().filter_map(|hop| hop.addr).collect();

                if unique_addresses.len() == 1
                    && unique_addresses.contains(&"127.0.0.1".parse().unwrap())
                {
                    eprintln!(
                        "Skipping test: all responses from localhost (test environment issue)"
                    );
                    return;
                }

                // We should see at least 3 hops for internet destinations
                assert!(
                    result.hop_count() >= 3,
                    "Expected at least 3 hops, got {}",
                    result.hop_count()
                );

                // Verify we have responses from different addresses
                assert!(
                    unique_addresses.len() >= 2,
                    "Expected responses from at least 2 different addresses, got {}",
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
    async fn test_localhost_single_hop() {
        // Localhost should always be a single hop
        let target = "127.0.0.1";

        match trace(target).await {
            Ok(result) => {
                assert_eq!(result.hop_count(), 1, "Localhost should be exactly 1 hop");
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
