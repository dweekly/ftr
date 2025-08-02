//! Debug test for Linux async UDP implementation

#[cfg(all(feature = "async", target_os = "linux"))]
#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use std::time::Duration;

    #[tokio::test]
    async fn test_linux_async_udp_recverr() {
        eprintln!("\n=== Linux Async UDP IP_RECVERR Debug Test ===");

        // Test environment
        eprintln!("Environment:");
        eprintln!("  CI: {:?}", std::env::var("CI"));
        eprintln!("  USER: {:?}", std::env::var("USER"));
        eprintln!("  GITHUB_ACTIONS: {:?}", std::env::var("GITHUB_ACTIONS"));

        // Test creating socket with IP_RECVERR
        eprintln!("\nTesting UDP socket with IP_RECVERR:");
        match std::net::UdpSocket::bind("0.0.0.0:0") {
            Ok(socket) => {
                eprintln!("  ✓ Created UDP socket");

                // Note: Can't test IP_RECVERR directly from test without libc dependency
                eprintln!("  (IP_RECVERR test skipped - would require libc in test dependencies)");

                // Set TTL to 1
                if let Err(e) = socket.set_ttl(1) {
                    eprintln!("  ✗ Failed to set TTL: {}", e);
                    return;
                }
                eprintln!("  ✓ Set TTL to 1");

                // Try to send a packet to 8.8.8.8
                let dest = "8.8.8.8:33434".parse::<std::net::SocketAddr>().unwrap();
                match socket.send_to(b"test", dest) {
                    Ok(n) => eprintln!("  ✓ Sent {} bytes to {}", n, dest),
                    Err(e) => eprintln!("  ✗ Failed to send: {}", e),
                }

                // Try to read from error queue
                eprintln!("\nChecking error queue:");
                eprintln!("  (Error queue test skipped - would require libc in test dependencies)");
            }
            Err(e) => {
                eprintln!("  ✗ Failed to create UDP socket: {}", e);
            }
        }

        // Now test the actual async implementation
        eprintln!("\nTesting actual async UDP implementation:");
        use ftr::probe::ProbeInfo;
        use ftr::socket::async_trait::AsyncProbeSocket;
        use ftr::socket::linux_async::LinuxAsyncUdpSocket;

        match LinuxAsyncUdpSocket::new() {
            Ok(socket) => {
                eprintln!("  ✓ Created LinuxAsyncUdpSocket");

                let dest: IpAddr = "8.8.8.8".parse().unwrap();
                let probe = ProbeInfo {
                    ttl: 1,
                    sequence: 1,
                    sent_at: std::time::Instant::now(),
                };

                eprintln!("  Sending probe to {} with TTL=1...", dest);

                // Use a shorter timeout for testing
                let result = tokio::time::timeout(
                    Duration::from_secs(2),
                    socket.send_probe_and_recv(dest, probe),
                )
                .await;

                match result {
                    Ok(Ok(response)) => {
                        eprintln!(
                            "  ✓ Got response from {} (timeout: {})",
                            response.from_addr, response.is_timeout
                        );
                    }
                    Ok(Err(e)) => {
                        eprintln!("  ✗ Probe failed: {}", e);
                    }
                    Err(_) => {
                        eprintln!("  ⚠ Probe timed out after 2 seconds");
                    }
                }
            }
            Err(e) => {
                eprintln!("  ✗ Failed to create LinuxAsyncUdpSocket: {}", e);
            }
        }
    }
}
