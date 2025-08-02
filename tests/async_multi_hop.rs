//! Test that async implementations show multiple hops

#[cfg(feature = "async")]
#[cfg(test)]
mod tests {
    use ftr::{trace, TracerouteConfig};
    use std::os::unix::io::AsRawFd;

    #[tokio::test]
    #[cfg_attr(not(any(target_os = "linux", target_os = "macos")), ignore)]
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

                // If we got no responses at all, there's a bug in the async UDP implementation
                if hops_with_responses.is_empty() && cfg!(target_os = "linux") {
                    eprintln!("\n=== DEBUG: Linux async UDP got 0 responses ===");
                    eprintln!("Environment info:");
                    eprintln!("  USER: {:?}", std::env::var("USER"));
                    eprintln!("  CI: {:?}", std::env::var("CI"));
                    eprintln!("  GITHUB_ACTIONS: {:?}", std::env::var("GITHUB_ACTIONS"));

                    // Check if we can create UDP socket with IP_RECVERR
                    eprintln!("\nTesting UDP socket creation with IP_RECVERR...");
                    if let Ok(socket) = std::net::UdpSocket::bind("0.0.0.0:0") {
                        let fd = socket.as_raw_fd();
                        unsafe {
                            let enable: i32 = 1;
                            let ret = libc::setsockopt(
                                fd,
                                libc::IPPROTO_IP,
                                libc::IP_RECVERR,
                                &enable as *const _ as *const libc::c_void,
                                std::mem::size_of::<i32>() as libc::socklen_t,
                            );
                            if ret == 0 {
                                eprintln!("  ✓ IP_RECVERR can be enabled");
                            } else {
                                eprintln!(
                                    "  ✗ Failed to enable IP_RECVERR: {}",
                                    std::io::Error::last_os_error()
                                );
                            }
                        }
                    }

                    // Test if sync mode works
                    eprintln!("\nTesting sync mode to compare...");
                    let sync_config = TracerouteConfig::builder()
                        .target(target)
                        .sync_mode(true)
                        .build()
                        .unwrap();

                    if let Ok(sync_result) = ftr::trace_with_config(sync_config).await {
                        let sync_responses: Vec<_> = sync_result
                            .hops
                            .iter()
                            .filter(|hop| hop.addr.is_some())
                            .collect();
                        eprintln!("Sync mode: {} hops with responses", sync_responses.len());

                        // Show some details about sync responses
                        for (i, hop) in sync_result.hops.iter().take(5).enumerate() {
                            if let Some(addr) = hop.addr {
                                eprintln!("  Hop {}: {} (RTT: {:?})", i + 1, addr, hop.rtt);
                            }
                        }

                        if !sync_responses.is_empty() {
                            panic!(
                                "BUG: Sync UDP works ({} responses) but async UDP doesn't work (0 responses)\n\
                                This indicates a bug in the Linux async UDP implementation.",
                                sync_responses.len()
                            );
                        }
                    }

                    eprintln!("\nBoth sync and async UDP modes failed to get responses");
                    eprintln!("This might be a network restriction in the CI environment");
                    eprintln!("Consider that GitHub Actions may block UDP traceroute entirely.");
                    return;
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
