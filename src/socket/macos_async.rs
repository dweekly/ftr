//! macOS async ICMP socket using per-probe sockets
//!
//! This module implements an async ICMP socket for macOS that creates
//! a new DGRAM ICMP socket for each probe, similar to the Linux approach.
//! This avoids issues with macOS DGRAM ICMP sockets not receiving
//! TimeExceeded messages when used with async I/O.

use crate::probe::{ProbeInfo, ProbeResponse};
use crate::socket::async_trait::{AsyncProbeSocket, ProbeMode};
use crate::trace_time;
use crate::TimingConfig;
use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use pnet::packet::icmp::echo_request::MutableEchoRequestPacket;
use pnet::packet::icmp::{echo_reply, IcmpPacket, IcmpTypes};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::Packet;
use pnet::util::checksum as pnet_checksum;
use socket2::{Domain, Protocol, Socket as Socket2, Type};
use std::mem::MaybeUninit;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::oneshot;

/// Size of ICMP echo payload
const ICMP_ECHO_PAYLOAD_SIZE: usize = 16;
/// ICMP error header length in bytes
const ICMP_ERROR_HEADER_LEN_BYTES: usize = 8;
/// IPv4 header minimum length in bytes
const IPV4_HEADER_MIN_LEN_BYTES: usize = 20;

/// macOS async ICMP socket implementation using per-probe sockets
pub struct MacOSAsyncIcmpSocket {
    icmp_identifier: u16,
    destination_reached: Arc<AtomicBool>,
    pending_count: Arc<AtomicUsize>,
    timing_config: TimingConfig,
    verbose: u8,
}

impl MacOSAsyncIcmpSocket {
    /// Create a new macOS async ICMP socket
    pub fn new() -> Result<Self> {
        Self::new_with_config(TimingConfig::default())
    }

    /// Create a new macOS async ICMP socket with timing configuration
    pub fn new_with_config(timing_config: TimingConfig) -> Result<Self> {
        let verbose = std::env::var("FTR_VERBOSE")
            .ok()
            .and_then(|v| v.parse::<u8>().ok())
            .unwrap_or(0);
        trace_time!(
            verbose,
            "Creating macOS async ICMP socket (per-probe version)"
        );

        Ok(Self {
            icmp_identifier: std::process::id() as u16,
            destination_reached: Arc::new(AtomicBool::new(false)),
            pending_count: Arc::new(AtomicUsize::new(0)),
            timing_config,
            verbose,
        })
    }

    /// Parse an ICMP response
    fn parse_response(
        &self,
        packet_data: &[u8],
        from_addr: IpAddr,
        recv_time: Instant,
        expected_sequence: u16,
        dest: IpAddr,
    ) -> Option<ProbeResponse> {
        // Parse outer IPv4 packet
        let outer_ipv4_packet = Ipv4Packet::new(packet_data)?;
        let icmp_data = outer_ipv4_packet.payload();
        let icmp_packet = IcmpPacket::new(icmp_data)?;

        trace_time!(
            self.verbose,
            "Received ICMP type {:?} code {:?} from {}",
            icmp_packet.get_icmp_type(),
            icmp_packet.get_icmp_code(),
            from_addr
        );

        match icmp_packet.get_icmp_type() {
            IcmpTypes::TimeExceeded | IcmpTypes::DestinationUnreachable => {
                // Parse the original packet that triggered this response
                let original_datagram_bytes = if icmp_data.len() >= ICMP_ERROR_HEADER_LEN_BYTES {
                    &icmp_data[ICMP_ERROR_HEADER_LEN_BYTES..]
                } else {
                    return None;
                };

                if original_datagram_bytes.len() < IPV4_HEADER_MIN_LEN_BYTES {
                    return None;
                }

                let inner_ip_packet = Ipv4Packet::new(original_datagram_bytes)?;
                let original_icmp_bytes = inner_ip_packet.payload();

                if original_icmp_bytes.len() < 8 {
                    return None;
                }

                // Extract identifier and sequence from original ICMP echo
                let original_type = original_icmp_bytes[0];
                let original_id =
                    u16::from_be_bytes([original_icmp_bytes[4], original_icmp_bytes[5]]);
                let original_seq =
                    u16::from_be_bytes([original_icmp_bytes[6], original_icmp_bytes[7]]);

                if original_type == IcmpTypes::EchoRequest.0
                    && original_id == self.icmp_identifier
                    && original_seq == expected_sequence
                {
                    let is_destination = matches!(
                        icmp_packet.get_icmp_type(),
                        IcmpTypes::DestinationUnreachable
                    );
                    return Some(ProbeResponse {
                        from_addr,
                        sequence: expected_sequence,
                        ttl: 0,                                   // Will be filled by caller
                        rtt: recv_time.duration_since(recv_time), // Will be calculated by caller
                        received_at: recv_time,
                        is_destination,
                        is_timeout: false,
                    });
                }
            }
            IcmpTypes::EchoReply => {
                if let Some(echo_reply_pkt) = echo_reply::EchoReplyPacket::new(icmp_packet.packet())
                {
                    if echo_reply_pkt.get_identifier() == self.icmp_identifier
                        && echo_reply_pkt.get_sequence_number() == expected_sequence
                    {
                        let is_destination = from_addr == dest;
                        return Some(ProbeResponse {
                            from_addr,
                            sequence: expected_sequence,
                            ttl: 0, // Will be filled by caller
                            rtt: recv_time.duration_since(recv_time), // Will be calculated by caller
                            received_at: recv_time,
                            is_destination,
                            is_timeout: false,
                        });
                    }
                }
            }
            _ => {}
        }

        None
    }

    /// Send an ICMP echo request and wait for response
    async fn send_and_recv_probe(&self, dest: Ipv4Addr, probe: ProbeInfo) -> Result<ProbeResponse> {
        let send_start = probe.sent_at;

        // Create a new DGRAM ICMP socket for this probe
        let socket = Socket2::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4))
            .context("Failed to create ICMP socket")?;

        // Set TTL
        socket
            .set_ttl_v4(probe.ttl as u32)
            .context("Failed to set TTL")?;

        // Set non-blocking
        socket.set_nonblocking(true)?;

        // Build ICMP Echo Request packet
        let mut icmp_buf =
            vec![0u8; MutableEchoRequestPacket::minimum_packet_size() + ICMP_ECHO_PAYLOAD_SIZE];
        let mut echo_req_packet = MutableEchoRequestPacket::new(&mut icmp_buf)
            .ok_or_else(|| anyhow!("Failed to create ICMP packet"))?;

        echo_req_packet.set_icmp_type(IcmpTypes::EchoRequest);
        echo_req_packet.set_icmp_code(pnet::packet::icmp::IcmpCode(0));
        echo_req_packet.set_identifier(self.icmp_identifier);
        echo_req_packet.set_sequence_number(probe.sequence);

        // Create payload
        let payload_data = (self.icmp_identifier as u32) << 16 | (probe.sequence as u32);
        let payload_bytes = payload_data.to_be_bytes();
        let mut final_payload = vec![0u8; ICMP_ECHO_PAYLOAD_SIZE];
        let bytes_to_copy = payload_bytes.len().min(ICMP_ECHO_PAYLOAD_SIZE);
        final_payload[..bytes_to_copy].copy_from_slice(&payload_bytes[..bytes_to_copy]);
        echo_req_packet.set_payload(&final_payload);

        // Calculate checksum
        let checksum = pnet_checksum(echo_req_packet.packet(), 1);
        echo_req_packet.set_checksum(checksum);

        // Send the packet
        let dest_addr = SocketAddr::new(IpAddr::V4(dest), 0);
        socket
            .send_to(echo_req_packet.packet(), &dest_addr.into())
            .context("Failed to send ICMP packet")?;

        trace_time!(
            self.verbose,
            "Sent ICMP echo seq={} ttl={} to {}",
            probe.sequence,
            probe.ttl,
            dest
        );

        // Create channel for response
        let (tx, rx) = oneshot::channel();

        // Spawn task to receive response
        let socket_clone = socket.try_clone()?;
        let icmp_identifier = self.icmp_identifier;
        let sequence = probe.sequence;
        let ttl = probe.ttl;
        let dest_ip = IpAddr::V4(dest);
        let verbose = self.verbose;
        let destination_reached = Arc::clone(&self.destination_reached);
        let pending_count = Arc::clone(&self.pending_count);

        tokio::spawn(async move {
            let mut buf = vec![MaybeUninit::uninit(); 1500];
            let timeout = Duration::from_millis(1000);
            let deadline = Instant::now() + timeout;

            loop {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    trace_time!(verbose, "Timeout waiting for response to seq={}", sequence);
                    break;
                }

                // Use tokio::time::timeout for async waiting
                let result = tokio::time::timeout(remaining, async {
                    // Poll the socket in a loop
                    loop {
                        match socket_clone.recv_from(&mut buf[..]) {
                            Ok((size, addr)) => {
                                return Ok((size, addr));
                            }
                            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                tokio::time::sleep(Duration::from_millis(1)).await;
                                continue;
                            }
                            Err(e) => return Err(e),
                        }
                    }
                })
                .await;

                match result {
                    Ok(Ok((size, addr))) => {
                        let recv_time = Instant::now();
                        let from_addr = match addr.as_socket_ipv4() {
                            Some(ipv4) => IpAddr::V4(*ipv4.ip()),
                            None => continue,
                        };

                        trace_time!(verbose, "Received {} bytes from {}", size, from_addr);

                        // Convert MaybeUninit buffer to initialized slice
                        let initialized_buf =
                            unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, size) };

                        // Try to parse the response - create a temporary parser
                        let parser = MacOSAsyncIcmpSocket {
                            icmp_identifier,
                            destination_reached: Arc::new(AtomicBool::new(false)),
                            pending_count: Arc::new(AtomicUsize::new(0)),
                            timing_config: TimingConfig::default(),
                            verbose,
                        };

                        if let Some(mut response) = parser.parse_response(
                            initialized_buf,
                            from_addr,
                            recv_time,
                            sequence,
                            dest_ip,
                        ) {
                            // Fill in the actual values
                            response.ttl = ttl;
                            response.rtt = recv_time.duration_since(send_start);

                            trace_time!(
                                verbose,
                                "Matched response for seq={} from {} rtt={:?}",
                                sequence,
                                from_addr,
                                response.rtt
                            );

                            // Update destination reached
                            if response.is_destination {
                                destination_reached.store(true, Ordering::Relaxed);
                            }

                            // Decrement pending count
                            pending_count.fetch_sub(1, Ordering::Relaxed);

                            let _ = tx.send(response);
                            return;
                        }
                    }
                    Ok(Err(e)) => {
                        trace_time!(verbose, "Error receiving: {}", e);
                        break;
                    }
                    Err(_) => {
                        // Timeout
                        break;
                    }
                }
            }

            // Send timeout response
            pending_count.fetch_sub(1, Ordering::Relaxed);
            let _ = tx.send(ProbeResponse {
                from_addr: dest_ip,
                sequence,
                ttl,
                rtt: Duration::from_millis(1000),
                received_at: Instant::now(),
                is_destination: false,
                is_timeout: true,
            });
        });

        // Wait for response
        match tokio::time::timeout(self.timing_config.socket_read_timeout, rx).await {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(_)) => {
                // Channel closed
                Err(anyhow!("Response channel closed unexpectedly"))
            }
            Err(_) => {
                // Timeout
                Ok(ProbeResponse {
                    from_addr: IpAddr::V4(dest),
                    sequence: probe.sequence,
                    ttl: probe.ttl,
                    rtt: self.timing_config.socket_read_timeout,
                    received_at: Instant::now(),
                    is_destination: false,
                    is_timeout: true,
                })
            }
        }
    }
}

#[async_trait]
impl AsyncProbeSocket for MacOSAsyncIcmpSocket {
    fn mode(&self) -> ProbeMode {
        ProbeMode::DgramIcmp
    }

    async fn send_probe_and_recv(&self, dest: IpAddr, probe: ProbeInfo) -> Result<ProbeResponse> {
        let dest_v4 = match dest {
            IpAddr::V4(addr) => addr,
            _ => return Err(anyhow!("Only IPv4 is supported")),
        };

        // Increment pending count
        self.pending_count.fetch_add(1, Ordering::Relaxed);

        self.send_and_recv_probe(dest_v4, probe).await
    }

    fn destination_reached(&self) -> bool {
        self.destination_reached.load(Ordering::Relaxed)
    }

    fn pending_count(&self) -> usize {
        self.pending_count.load(Ordering::Relaxed)
    }
}

// Safety: The socket and shared state are properly synchronized
unsafe impl Send for MacOSAsyncIcmpSocket {}
unsafe impl Sync for MacOSAsyncIcmpSocket {}
