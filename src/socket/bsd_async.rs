//! BSD async ICMP socket implementation
//!
//! This implementation works for FreeBSD, OpenBSD, NetBSD, and DragonFly BSD.
//! All BSDs use raw ICMP sockets which require root privileges.
//! Unlike macOS, other BSDs do not support DGRAM ICMP sockets.
//!
//! The BSD raw ICMP implementation is essentially the same across all BSD variants,
//! using the standard POSIX socket API with raw sockets.

use crate::probe::{ProbeInfo, ProbeResponse};
use crate::socket::async_trait::{AsyncProbeSocket, ProbeMode};
use crate::TimingConfig;
use anyhow::{Context, Result};
use async_trait::async_trait;
use pnet::packet::{MutablePacket, Packet};
use socket2::{Domain, Protocol, Socket as Socket2, Type};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::oneshot;

/// BSD async ICMP socket implementation
pub struct BsdAsyncIcmpSocket {
    mode: ProbeMode,
    icmp_identifier: u16,
    destination_reached: Arc<AtomicBool>,
    pending_count: Arc<AtomicUsize>,
    timing_config: TimingConfig,
}

impl BsdAsyncIcmpSocket {
    /// Create a new BSD async ICMP socket
    pub fn new() -> Result<Self> {
        Self::new_with_config(TimingConfig::default())
    }

    /// Create a new BSD async ICMP socket with custom timing configuration
    pub fn new_with_config(timing_config: TimingConfig) -> Result<Self> {
        let icmp_identifier = std::process::id() as u16;

        // Platform-specific adjustments can go here
        #[cfg(target_os = "openbsd")]
        {
            // OpenBSD might have specific requirements or optimizations
            // For example, checking for pledge/unveil compatibility
        }

        Ok(BsdAsyncIcmpSocket {
            mode: ProbeMode::RawIcmp,
            icmp_identifier,
            destination_reached: Arc::new(AtomicBool::new(false)),
            pending_count: Arc::new(AtomicUsize::new(0)),
            timing_config,
        })
    }

    /// Create ICMP echo request packet
    fn create_echo_request(&self, sequence: u16) -> Vec<u8> {
        use pnet::packet::icmp::echo_request::MutableEchoRequestPacket;
        use pnet::packet::icmp::IcmpTypes;
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
            let checksum = checksum(&icmp_packet.packet(), 1);
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

#[async_trait]
impl AsyncProbeSocket for BsdAsyncIcmpSocket {
    fn mode(&self) -> ProbeMode {
        self.mode
    }

    async fn send_probe_and_recv(&self, dest: IpAddr, probe: ProbeInfo) -> Result<ProbeResponse> {
        // Increment pending count
        self.pending_count.fetch_add(1, Ordering::Relaxed);

        // Create raw ICMP socket
        let socket = Socket2::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))
            .context("Failed to create raw ICMP socket")?;

        // Platform-specific socket options could be set here
        #[cfg(target_os = "openbsd")]
        {
            // OpenBSD might need specific socket options
            // e.g., different buffer sizes or security flags
        }

        // Set TTL
        socket
            .set_ttl_v4(probe.ttl as u32)
            .context("Failed to set TTL")?;

        // Set non-blocking
        socket.set_nonblocking(true)?;

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
        let timeout = self.timing_config.socket_read_timeout;

        // Create oneshot channel for response
        let (tx, rx) = oneshot::channel();

        // Spawn task to read responses
        let socket = Arc::new(socket);
        let socket_clone = socket.clone();
        tokio::spawn(async move {
            let start = Instant::now();

            loop {
                // Try to receive response
                let mut buf = vec![std::mem::MaybeUninit::uninit(); 1500];
                match socket_clone.recv_from(&mut buf) {
                    Ok((size, addr)) => {
                        if let Some(from_addr) = addr.as_socket_ipv4() {
                            let from_ip = IpAddr::V4(*from_addr.ip());

                            // Convert MaybeUninit buffer to initialized slice
                            let initialized_buf = unsafe {
                                std::slice::from_raw_parts(buf.as_ptr() as *const u8, size)
                            };

                            // Parse ICMP response
                            let parser = BsdAsyncIcmpSocket {
                                mode: ProbeMode::RawIcmp,
                                icmp_identifier,
                                destination_reached: Arc::new(AtomicBool::new(false)),
                                pending_count: Arc::new(AtomicUsize::new(0)),
                                timing_config: TimingConfig::default(),
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

                // Check timeout
                if start.elapsed() >= timeout {
                    // Timeout
                    pending_count.fetch_sub(1, Ordering::Relaxed);
                    let _ = tx.send(ProbeResponse {
                        from_addr: dest,
                        sequence,
                        ttl,
                        rtt: timeout,
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

// Safety: The socket is protected by Arc<AtomicBool> and Arc<AtomicUsize>
unsafe impl Send for BsdAsyncIcmpSocket {}
unsafe impl Sync for BsdAsyncIcmpSocket {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_socket() {
        // This will fail without root
        let result = BsdAsyncIcmpSocket::new();
        if !crate::socket::utils::is_root() {
            assert!(result.is_err());
        }
    }
}
