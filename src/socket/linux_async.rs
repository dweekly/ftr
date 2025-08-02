//! Linux async socket implementation for traceroute
//!
//! This module provides async UDP traceroute using IP_RECVERR for non-root operation.

use super::async_trait::{AsyncProbeSocket, ProbeMode};
use crate::probe::{ProbeInfo, ProbeResponse};
use anyhow::{Context, Result};
use pnet::packet::{MutablePacket, Packet};
use std::mem;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::oneshot;

// Linux specific constants for IP_RECVERR
const SO_EE_ORIGIN_ICMP: u8 = 2;

// sock_extended_err structure from Linux
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct SockExtendedErr {
    ee_errno: u32,
    ee_origin: u8,
    ee_type: u8,
    ee_code: u8,
    ee_pad: u8,
    ee_info: u32,
    ee_data: u32,
}

/// Async UDP socket for Linux using IP_RECVERR
pub struct LinuxAsyncUdpSocket {
    mode: ProbeMode,
    destination_reached: Arc<AtomicBool>,
    pending_count: Arc<AtomicUsize>,
    dest_port: u16,
}

/// Result of checking for ICMP error
enum IcmpCheckResult {
    /// Found a matching response
    Found(IpAddr, bool), // (from_addr, is_destination)
    /// No data available yet
    NoData,
    /// Error occurred
    Error,
}

impl LinuxAsyncUdpSocket {
    /// Check for ICMP error using MSG_ERRQUEUE
    unsafe fn check_icmp_error(fd: i32, _sequence: u16) -> IcmpCheckResult {
        let mut buf = [0u8; 512];
        let mut control_buf = [0u8; 512];
        let mut from_addr: libc::sockaddr_in = std::mem::zeroed();
        let from_len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;

        // Debug logging in CI
        if std::env::var("CI").is_ok() {
            static mut CHECK_COUNT: u32 = 0;
            CHECK_COUNT += 1;
            if CHECK_COUNT <= 5 || CHECK_COUNT % 100 == 0 {
                eprintln!(
                    "[DEBUG] check_icmp_error: attempt {} on fd {}",
                    CHECK_COUNT, fd
                );
            }
        }

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
            // Debug logging in CI
            if std::env::var("CI").is_ok() {
                eprintln!("[DEBUG] recvmsg returned {} bytes", ret);
            }

            // Parse control messages to find IP_RECVERR
            let mut cmsg: *const libc::cmsghdr = libc::CMSG_FIRSTHDR(&msg);

            while !cmsg.is_null() {
                let cmsg_data = std::ptr::read_unaligned(cmsg);

                if cmsg_data.cmsg_level == libc::IPPROTO_IP
                    && cmsg_data.cmsg_type == libc::IP_RECVERR
                {
                    let err_ptr = libc::CMSG_DATA(cmsg) as *const SockExtendedErr;
                    let sock_err = std::ptr::read_unaligned(err_ptr);

                    if sock_err.ee_origin == SO_EE_ORIGIN_ICMP {
                        // Get the offending address (follows the SockExtendedErr structure)
                        let addr_ptr = (err_ptr as *const u8).add(mem::size_of::<SockExtendedErr>())
                            as *const libc::sockaddr_in;
                        let offender_addr = std::ptr::read_unaligned(addr_ptr);
                        let from_ip =
                            IpAddr::V4(Ipv4Addr::from(u32::from_be(offender_addr.sin_addr.s_addr)));

                        // Since we're using a dedicated socket per probe, any error on this socket
                        // must be for our probe. We don't need to check identifier/sequence.
                        // Determine if this is destination (Port Unreachable)
                        let is_destination = sock_err.ee_type == 3 && sock_err.ee_code == 3;

                        // Debug logging in CI
                        if std::env::var("CI").is_ok() {
                            eprintln!(
                                "[DEBUG] ICMP response: from={}, type={}, code={}, is_dest={}",
                                from_ip, sock_err.ee_type, sock_err.ee_code, is_destination
                            );
                        }

                        return IcmpCheckResult::Found(from_ip, is_destination);
                    }
                }

                cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
            }
            IcmpCheckResult::NoData
        } else {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EAGAIN) {
                IcmpCheckResult::NoData
            } else {
                // Debug logging in CI
                if std::env::var("CI").is_ok() {
                    static mut ERR_COUNT: u32 = 0;
                    unsafe {
                        ERR_COUNT += 1;
                        if ERR_COUNT <= 5 {
                            eprintln!("[DEBUG] recvmsg error: {}", err);
                        }
                    }
                }
                IcmpCheckResult::Error
            }
        }
    }

    /// Create a new async UDP socket with IP_RECVERR for Linux
    pub fn new() -> Result<Self> {
        Self::new_with_config(crate::TimingConfig::default())
    }

    /// Create with timing configuration
    pub fn new_with_config(_timing_config: crate::TimingConfig) -> Result<Self> {
        let dest_port = 33434; // Traditional traceroute port

        Ok(LinuxAsyncUdpSocket {
            mode: ProbeMode::UdpWithRecverr,
            destination_reached: Arc::new(AtomicBool::new(false)),
            pending_count: Arc::new(AtomicUsize::new(0)),
            dest_port,
        })
    }
}

#[async_trait::async_trait]
impl AsyncProbeSocket for LinuxAsyncUdpSocket {
    fn mode(&self) -> ProbeMode {
        self.mode
    }

    async fn send_probe_and_recv(&self, dest: IpAddr, probe: ProbeInfo) -> Result<ProbeResponse> {
        // Increment pending count
        self.pending_count.fetch_add(1, Ordering::Relaxed);

        // Create a new UDP socket for this probe
        let socket =
            std::net::UdpSocket::bind("0.0.0.0:0").context("Failed to create UDP socket")?;

        let fd = socket.as_raw_fd();

        // Enable IP_RECVERR
        unsafe {
            let enable: i32 = 1;
            let ret = libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_RECVERR,
                &enable as *const _ as *const libc::c_void,
                std::mem::size_of::<i32>() as libc::socklen_t,
            );
            if ret != 0 {
                self.pending_count.fetch_sub(1, Ordering::Relaxed);
                return Err(anyhow::anyhow!("Failed to set IP_RECVERR"));
            }
        }

        // Set TTL
        socket
            .set_ttl(probe.ttl as u32)
            .context("Failed to set TTL")?;

        // Set non-blocking
        socket.set_nonblocking(true)?;

        // Convert to Tokio socket
        let async_socket = UdpSocket::from_std(socket)?;

        // Connect to destination
        let target_addr = SocketAddr::new(dest, self.dest_port);
        async_socket.connect(target_addr).await?;

        // Create payload
        let identifier = std::process::id() as u16;
        let mut payload = Vec::with_capacity(32);
        payload.extend_from_slice(&identifier.to_be_bytes());
        payload.extend_from_slice(&probe.sequence.to_be_bytes());
        payload.extend_from_slice(b"ftr-traceroute-probe-padding");

        // Record send time
        let sent_at = Instant::now();

        // Send probe
        let bytes_sent = async_socket.send(&payload).await?;

        // Debug logging in CI
        if std::env::var("CI").is_ok() {
            eprintln!(
                "[DEBUG] UDP probe sent: {} bytes to {}, TTL={}, seq={}",
                bytes_sent, target_addr, probe.ttl, probe.sequence
            );
        }

        // Clone necessary data for the spawned task
        let destination_reached = self.destination_reached.clone();
        let pending_count = self.pending_count.clone();
        let sequence = probe.sequence;
        let ttl = probe.ttl;

        // Create oneshot channel for response
        let (tx, rx) = oneshot::channel();

        // Get the raw fd before moving the socket
        let fd = async_socket.as_raw_fd();

        // Spawn task to read from error queue
        tokio::spawn(async move {
            // Keep the socket alive in this task
            let _socket_guard = async_socket;
            let mut retry_count = 0;
            const MAX_RETRIES: u32 = 1000; // 1 second with 1ms delays

            loop {
                // Check for ICMP error using MSG_ERRQUEUE
                let result = unsafe { LinuxAsyncUdpSocket::check_icmp_error(fd, sequence) };

                match result {
                    IcmpCheckResult::Found(from_addr, is_destination) => {
                        let rtt = Instant::now().duration_since(sent_at);

                        // Update destination reached
                        if is_destination {
                            destination_reached.store(true, Ordering::Relaxed);
                        }

                        // Decrement pending count
                        pending_count.fetch_sub(1, Ordering::Relaxed);

                        let response = ProbeResponse {
                            from_addr,
                            sequence,
                            ttl,
                            rtt,
                            received_at: Instant::now(),
                            is_destination,
                            is_timeout: false,
                        };

                        let _ = tx.send(response);
                        break;
                    }
                    IcmpCheckResult::Error => {
                        // Actual error
                        pending_count.fetch_sub(1, Ordering::Relaxed);
                        break;
                    }
                    IcmpCheckResult::NoData => {
                        // No data yet, continue polling
                    }
                }

                retry_count += 1;
                if retry_count >= MAX_RETRIES {
                    // Timeout
                    pending_count.fetch_sub(1, Ordering::Relaxed);
                    let _ = tx.send(ProbeResponse {
                        from_addr: dest,
                        sequence,
                        ttl,
                        rtt: Duration::from_secs(1),
                        received_at: Instant::now(),
                        is_destination: false,
                        is_timeout: true,
                    });
                    break;
                }

                // Brief yield before retrying
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        });

        // Wait for response
        match rx.await {
            Ok(response) => Ok(response),
            Err(_) => {
                // Channel closed without response
                self.pending_count.fetch_sub(1, Ordering::Relaxed);
                Err(anyhow::anyhow!("Failed to receive response"))
            }
        }
    }

    fn destination_reached(&self) -> bool {
        self.destination_reached.load(Ordering::Relaxed)
    }

    fn pending_count(&self) -> usize {
        self.pending_count.load(Ordering::Relaxed)
    }
}

/// Async ICMP socket for Linux (requires root or CAP_NET_RAW)
pub struct LinuxAsyncIcmpSocket {
    mode: ProbeMode,
    icmp_identifier: u16,
    destination_reached: Arc<AtomicBool>,
    pending_count: Arc<AtomicUsize>,
}

impl LinuxAsyncIcmpSocket {
    /// Create a new async ICMP socket for Linux
    pub fn new() -> Result<Self> {
        Self::new_with_config(crate::TimingConfig::default())
    }

    /// Create with timing configuration
    pub fn new_with_config(_timing_config: crate::TimingConfig) -> Result<Self> {
        let icmp_identifier = std::process::id() as u16;

        Ok(LinuxAsyncIcmpSocket {
            mode: ProbeMode::RawIcmp,
            icmp_identifier,
            destination_reached: Arc::new(AtomicBool::new(false)),
            pending_count: Arc::new(AtomicUsize::new(0)),
        })
    }

    /// Create ICMP echo request packet
    fn create_echo_request(&self, sequence: u16) -> Vec<u8> {
        use pnet::packet::icmp::echo_request::MutableEchoRequestPacket;
        use pnet::packet::icmp::IcmpTypes;
        use pnet::packet::Packet;
        use pnet::util::checksum;

        const ICMP_HEADER_SIZE: usize = 8;
        const ICMP_PAYLOAD_SIZE: usize = 16;
        const PACKET_SIZE: usize = ICMP_HEADER_SIZE + ICMP_PAYLOAD_SIZE;

        let mut buf = vec![0u8; PACKET_SIZE];

        // Create ICMP packet
        if let Some(mut packet) = MutableEchoRequestPacket::new(&mut buf) {
            packet.set_icmp_type(IcmpTypes::EchoRequest);
            packet.set_identifier(self.icmp_identifier);
            packet.set_sequence_number(sequence);

            // Set payload
            let payload = b"ftr-traceroute";
            let payload_slice = packet.payload_mut();
            payload_slice[..payload.len()].copy_from_slice(payload);

            // Calculate checksum
            let icmp_packet = packet.to_immutable();
            let checksum = checksum(icmp_packet.packet(), 1);
            packet.set_checksum(checksum);
        }

        buf
    }

    /// Parse ICMP response
    fn parse_icmp_response(
        &self,
        data: &[u8],
        from_addr: IpAddr,
        sequence: u16,
    ) -> Option<(IpAddr, bool)> {
        use pnet::packet::icmp::{echo_reply, IcmpPacket, IcmpTypes};
        use pnet::packet::ipv4::Ipv4Packet;

        // Parse IPv4 packet
        let ipv4_packet = Ipv4Packet::new(data)?;
        let icmp_data = ipv4_packet.payload();
        let icmp_packet = IcmpPacket::new(icmp_data)?;

        match icmp_packet.get_icmp_type() {
            IcmpTypes::EchoReply => {
                // Parse echo reply
                if let Some(echo_reply) = echo_reply::EchoReplyPacket::new(icmp_data) {
                    if echo_reply.get_identifier() == self.icmp_identifier
                        && echo_reply.get_sequence_number() == sequence
                    {
                        return Some((from_addr, true)); // is_destination = true
                    }
                }
            }
            IcmpTypes::TimeExceeded => {
                // Extract original packet from ICMP error
                const ICMP_ERROR_HEADER_LEN: usize = 8;
                const IPV4_HEADER_MIN_LEN: usize = 20;

                if icmp_data.len() >= ICMP_ERROR_HEADER_LEN + IPV4_HEADER_MIN_LEN {
                    let inner_data = &icmp_data[ICMP_ERROR_HEADER_LEN..];
                    if let Some(inner_ipv4) = Ipv4Packet::new(inner_data) {
                        let inner_icmp_data = inner_ipv4.payload();

                        // Check if this is our packet by examining the first 8 bytes
                        if inner_icmp_data.len() >= 8 {
                            let inner_type = inner_icmp_data[0];
                            if inner_type == 8 {
                                // Echo Request
                                let identifier =
                                    u16::from_be_bytes([inner_icmp_data[4], inner_icmp_data[5]]);
                                let seq =
                                    u16::from_be_bytes([inner_icmp_data[6], inner_icmp_data[7]]);

                                if identifier == self.icmp_identifier && seq == sequence {
                                    return Some((from_addr, false)); // is_destination = false
                                }
                            }
                        }
                    }
                }
            }
            IcmpTypes::DestinationUnreachable => {
                // Similar to TimeExceeded, extract original packet
                const ICMP_ERROR_HEADER_LEN: usize = 8;
                const IPV4_HEADER_MIN_LEN: usize = 20;

                if icmp_data.len() >= ICMP_ERROR_HEADER_LEN + IPV4_HEADER_MIN_LEN {
                    let inner_data = &icmp_data[ICMP_ERROR_HEADER_LEN..];
                    if let Some(inner_ipv4) = Ipv4Packet::new(inner_data) {
                        let inner_icmp_data = inner_ipv4.payload();

                        if inner_icmp_data.len() >= 8 {
                            let inner_type = inner_icmp_data[0];
                            if inner_type == 8 {
                                // Echo Request
                                let identifier =
                                    u16::from_be_bytes([inner_icmp_data[4], inner_icmp_data[5]]);
                                let seq =
                                    u16::from_be_bytes([inner_icmp_data[6], inner_icmp_data[7]]);

                                if identifier == self.icmp_identifier && seq == sequence {
                                    return Some((from_addr, false));
                                }
                            }
                        }
                    }
                }
            }
            _ => {}
        }

        None
    }
}

#[async_trait::async_trait]
impl AsyncProbeSocket for LinuxAsyncIcmpSocket {
    fn mode(&self) -> ProbeMode {
        self.mode
    }

    async fn send_probe_and_recv(&self, dest: IpAddr, probe: ProbeInfo) -> Result<ProbeResponse> {
        use socket2::{Domain, Protocol, Socket as Socket2, Type};
        use std::os::unix::io::AsRawFd;

        // Increment pending count
        self.pending_count.fetch_add(1, Ordering::Relaxed);

        // Create raw ICMP socket
        let socket = Socket2::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))
            .context("Failed to create raw ICMP socket")?;

        // Set TTL
        socket
            .set_ttl_v4(probe.ttl as u32)
            .context("Failed to set TTL")?;

        // Set non-blocking
        socket.set_nonblocking(true)?;

        // Convert to Tokio socket (we'll use it through raw fd)
        let _fd = socket.as_raw_fd();

        // Create ICMP echo request packet
        let packet = self.create_echo_request(probe.sequence);

        // Send packet
        let dest_addr: SocketAddr = SocketAddr::new(dest, 0);
        let sent_at = Instant::now();
        socket
            .send_to(&packet, &dest_addr.into())
            .context("Failed to send ICMP packet")?;

        // Clone necessary data for the spawned task
        let destination_reached = self.destination_reached.clone();
        let pending_count = self.pending_count.clone();
        let sequence = probe.sequence;
        let ttl = probe.ttl;
        let icmp_identifier = self.icmp_identifier;

        // Create oneshot channel for response
        let (tx, rx) = oneshot::channel();

        // Spawn task to read responses
        let socket = Arc::new(socket);
        let socket_clone = socket.clone();
        tokio::spawn(async move {
            let mut retry_count = 0;
            const MAX_RETRIES: u32 = 1000; // 1 second with 1ms delays

            loop {
                // Try to receive response
                let mut buf = [std::mem::MaybeUninit::uninit(); 1500];
                match socket_clone.recv_from(&mut buf) {
                    Ok((size, addr)) => {
                        if let Some(from_addr) = addr.as_socket_ipv4() {
                            let from_ip = IpAddr::V4(*from_addr.ip());

                            // Convert MaybeUninit buffer to initialized slice
                            let initialized_buf = unsafe {
                                std::slice::from_raw_parts(buf.as_ptr() as *const u8, size)
                            };

                            // Parse ICMP response
                            let parser = LinuxAsyncIcmpSocket {
                                mode: ProbeMode::RawIcmp,
                                icmp_identifier,
                                destination_reached: Arc::new(AtomicBool::new(false)),
                                pending_count: Arc::new(AtomicUsize::new(0)),
                            };

                            if let Some((resp_addr, is_destination)) =
                                parser.parse_icmp_response(initialized_buf, from_ip, sequence)
                            {
                                let rtt = Instant::now().duration_since(sent_at);

                                // Update destination reached
                                if is_destination {
                                    destination_reached.store(true, Ordering::Relaxed);
                                }

                                // Decrement pending count
                                pending_count.fetch_sub(1, Ordering::Relaxed);

                                let response = ProbeResponse {
                                    from_addr: resp_addr,
                                    sequence,
                                    ttl,
                                    rtt,
                                    received_at: Instant::now(),
                                    is_destination,
                                    is_timeout: false,
                                };

                                let _ = tx.send(response);
                                break;
                            }
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        // No data yet, continue
                    }
                    Err(_) => {
                        // Other error
                        pending_count.fetch_sub(1, Ordering::Relaxed);
                        break;
                    }
                }

                retry_count += 1;
                if retry_count >= MAX_RETRIES {
                    // Timeout
                    pending_count.fetch_sub(1, Ordering::Relaxed);
                    let _ = tx.send(ProbeResponse {
                        from_addr: dest,
                        sequence,
                        ttl,
                        rtt: Duration::from_secs(1),
                        received_at: Instant::now(),
                        is_destination: false,
                        is_timeout: true,
                    });
                    break;
                }

                // Brief yield before retrying
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        });

        // Wait for response
        match rx.await {
            Ok(response) => Ok(response),
            Err(_) => {
                // Channel closed without response
                self.pending_count.fetch_sub(1, Ordering::Relaxed);
                Err(anyhow::anyhow!("Failed to receive response"))
            }
        }
    }

    fn destination_reached(&self) -> bool {
        self.destination_reached.load(Ordering::Relaxed)
    }

    fn pending_count(&self) -> usize {
        self.pending_count.load(Ordering::Relaxed)
    }
}
