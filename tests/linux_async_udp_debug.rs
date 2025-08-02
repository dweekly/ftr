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

                let fd = socket.as_raw_fd();
                unsafe {
                    use std::os::unix::io::AsRawFd;
                    let enable: i32 = 1;
                    let ret = libc::setsockopt(
                        fd,
                        libc::IPPROTO_IP,
                        libc::IP_RECVERR,
                        &enable as *const _ as *const libc::c_void,
                        std::mem::size_of::<i32>() as libc::socklen_t,
                    );
                    if ret == 0 {
                        eprintln!("  ✓ Enabled IP_RECVERR");
                    } else {
                        eprintln!(
                            "  ✗ Failed to enable IP_RECVERR: {}",
                            std::io::Error::last_os_error()
                        );
                        return;
                    }
                }

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
                std::thread::sleep(Duration::from_millis(100)); // Give time for ICMP response

                unsafe {
                    let mut buf = [0u8; 512];
                    let mut control_buf = [0u8; 512];
                    let mut from_addr: libc::sockaddr_in = std::mem::zeroed();
                    let from_len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;

                    let mut iovec = libc::iovec {
                        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
                        iov_len: buf.len(),
                    };

                    let mut msg = libc::msghdr {
                        msg_name: &mut from_addr as *mut _ as *mut libc::c_void,
                        msg_namelen: from_len,
                        msg_iov: &mut iovec,
                        msg_iovlen: 1,
                        msg_control: control_buf.as_mut_ptr() as *mut libc::c_void,
                        msg_controllen: control_buf.len(),
                        msg_flags: 0,
                    };

                    let ret = libc::recvmsg(fd, &mut msg, libc::MSG_ERRQUEUE | libc::MSG_DONTWAIT);
                    if ret >= 0 {
                        eprintln!("  ✓ Received error queue message (size: {})", ret);
                    } else {
                        let err = std::io::Error::last_os_error();
                        if err.raw_os_error() == Some(libc::EAGAIN) {
                            eprintln!("  ⚠ No data in error queue (EAGAIN)");
                        } else {
                            eprintln!("  ✗ Error reading error queue: {}", err);
                        }
                    }
                }
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
