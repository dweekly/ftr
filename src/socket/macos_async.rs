//! macOS async ICMP socket using Tokio
//!
//! This module implements an async ICMP socket for macOS using DGRAM ICMP
//! sockets with Tokio's async primitives for immediate response notification.

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
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{oneshot, Mutex as TokioMutex};

/// Size of ICMP echo payload
const ICMP_ECHO_PAYLOAD_SIZE: usize = 16;
/// ICMP error header length in bytes
const ICMP_ERROR_HEADER_LEN_BYTES: usize = 8;
/// IPv4 header minimum length in bytes
const IPV4_HEADER_MIN_LEN_BYTES: usize = 20;

/// Pending probe information
#[derive(Debug)]
struct PendingProbe {
    probe_info: ProbeInfo,
    response_tx: oneshot::Sender<ProbeResponse>,
}

/// macOS async ICMP socket implementation using DGRAM sockets
pub struct MacOSAsyncIcmpSocket {
    socket: Arc<UdpSocket>,
    icmp_identifier: u16,
    pending_probes: Arc<TokioMutex<HashMap<u16, PendingProbe>>>,
    destination_reached: Arc<Mutex<bool>>,
    pending_count: Arc<Mutex<usize>>,
    timing_config: TimingConfig,
    verbose: u8,
    _receiver_task: tokio::task::JoinHandle<()>,
}

impl MacOSAsyncIcmpSocket {
    /// Create a new macOS async ICMP socket
    pub fn new_with_config(timing_config: TimingConfig) -> Result<Self> {
        let verbose = std::env::var("FTR_VERBOSE")
            .ok()
            .and_then(|v| v.parse::<u8>().ok())
            .unwrap_or(0);
        trace_time!(verbose, "Creating macOS async ICMP socket");

        // Create DGRAM ICMP socket (works without root on macOS)
        let socket = Socket2::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4))
            .context("Failed to create ICMP socket")?;

        // Bind to any available port
        socket
            .bind(&"0.0.0.0:0".parse::<SocketAddr>()?.into())
            .context("Failed to bind socket")?;

        // Set socket to non-blocking for async operation
        socket
            .set_nonblocking(true)
            .context("Failed to set socket non-blocking")?;

        // Convert to Tokio async socket
        let std_socket = std::net::UdpSocket::from(socket);
        let async_socket =
            UdpSocket::from_std(std_socket).context("Failed to create async socket")?;

        let socket = Arc::new(async_socket);
        let icmp_identifier = std::process::id() as u16;
        let pending_probes = Arc::new(TokioMutex::new(HashMap::new()));
        let destination_reached = Arc::new(Mutex::new(false));
        let pending_count = Arc::new(Mutex::new(0));

        // Start the receiver task
        let receiver_task = {
            let socket = Arc::clone(&socket);
            let pending_probes = Arc::clone(&pending_probes);
            let destination_reached = Arc::clone(&destination_reached);
            let pending_count = Arc::clone(&pending_count);
            let v = verbose;

            tokio::spawn(async move {
                Self::receiver_loop(
                    socket,
                    icmp_identifier,
                    pending_probes,
                    destination_reached,
                    pending_count,
                    v,
                )
                .await
            })
        };

        Ok(Self {
            socket,
            icmp_identifier,
            pending_probes,
            destination_reached,
            pending_count,
            timing_config,
            verbose,
            _receiver_task: receiver_task,
        })
    }

    /// Receiver loop that runs in the background
    async fn receiver_loop(
        socket: Arc<UdpSocket>,
        icmp_identifier: u16,
        pending_probes: Arc<TokioMutex<HashMap<u16, PendingProbe>>>,
        destination_reached: Arc<Mutex<bool>>,
        pending_count: Arc<Mutex<usize>>,
        verbose: u8,
    ) {
        let mut buf = vec![0u8; 1500];
        trace_time!(verbose, "Started async receiver loop");

        loop {
            match socket.recv_from(&mut buf).await {
                Ok((size, addr)) => {
                    let recv_time = Instant::now();
                    trace_time!(verbose, "Received {} bytes from {}", size, addr);

                    let _ = Self::parse_response(
                        &buf[..size],
                        addr.ip(),
                        recv_time,
                        icmp_identifier,
                        &pending_probes,
                        &destination_reached,
                        &pending_count,
                        verbose,
                    )
                    .await;
                }
                Err(e) => {
                    // Log error but continue receiving
                    if verbose > 0 {
                        eprintln!("Error receiving ICMP response: {}", e);
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
        }
    }

    /// Parse an ICMP response and send it to the waiting probe
    #[allow(clippy::too_many_arguments)]
    async fn parse_response(
        packet_data: &[u8],
        from_addr: IpAddr,
        recv_time: Instant,
        icmp_identifier: u16,
        pending_probes: &Arc<TokioMutex<HashMap<u16, PendingProbe>>>,
        destination_reached: &Arc<Mutex<bool>>,
        pending_count: &Arc<Mutex<usize>>,
        verbose: u8,
    ) -> Option<()> {
        // Parse outer IPv4 packet
        let outer_ipv4_packet = Ipv4Packet::new(packet_data)?;
        let icmp_data = outer_ipv4_packet.payload();
        let icmp_packet = IcmpPacket::new(icmp_data)?;

        let (sequence, is_destination) = match icmp_packet.get_icmp_type() {
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

                if original_type == IcmpTypes::EchoRequest.0 && original_id == icmp_identifier {
                    (
                        original_seq,
                        matches!(
                            icmp_packet.get_icmp_type(),
                            IcmpTypes::DestinationUnreachable
                        ),
                    )
                } else {
                    return None;
                }
            }
            IcmpTypes::EchoReply => {
                if let Some(echo_reply_pkt) = echo_reply::EchoReplyPacket::new(icmp_packet.packet())
                {
                    if echo_reply_pkt.get_identifier() == icmp_identifier {
                        (echo_reply_pkt.get_sequence_number(), true)
                    } else {
                        return None;
                    }
                } else {
                    return None;
                }
            }
            _ => return None,
        };

        // Look up and remove the pending probe
        let mut pending_probes = pending_probes.lock().await;
        if let Some(pending) = pending_probes.remove(&sequence) {
            let rtt = recv_time.duration_since(pending.probe_info.sent_at);
            trace_time!(
                verbose,
                "Matched probe seq={} ttl={} rtt={:?}",
                sequence,
                pending.probe_info.ttl,
                rtt
            );

            // Update destination reached status
            if is_destination {
                *destination_reached
                    .lock()
                    .expect("Failed to lock destination_reached") = true;
            }

            // Decrement pending count
            {
                let mut count = pending_count.lock().expect("Failed to lock pending_count");
                *count = count.saturating_sub(1);
            }

            // Create the response
            let response = ProbeResponse {
                from_addr,
                sequence: pending.probe_info.sequence,
                ttl: pending.probe_info.ttl,
                rtt: recv_time.duration_since(pending.probe_info.sent_at),
                received_at: recv_time,
                is_destination,
                is_timeout: false,
            };

            // Send the response through the oneshot channel
            let _ = pending.response_tx.send(response);

            Some(())
        } else {
            None
        }
    }

    /// Set TTL on the underlying socket
    async fn set_ttl_internal(&self, ttl: u8) -> Result<()> {
        // Get reference to the std socket to set TTL
        self.socket
            .as_ref()
            .set_ttl(ttl as u32)
            .context("Failed to set TTL")?;
        Ok(())
    }

    /// Send an ICMP echo request
    async fn send_icmp_echo(&self, dest: Ipv4Addr, sequence: u16, ttl: u8) -> Result<()> {
        let send_start = Instant::now();
        // Set TTL for this probe
        self.set_ttl_internal(ttl).await?;

        // Build ICMP Echo Request packet
        let mut icmp_buf =
            vec![0u8; MutableEchoRequestPacket::minimum_packet_size() + ICMP_ECHO_PAYLOAD_SIZE];
        let mut echo_req_packet = MutableEchoRequestPacket::new(&mut icmp_buf)
            .ok_or_else(|| anyhow!("Failed to create ICMP packet"))?;

        echo_req_packet.set_icmp_type(IcmpTypes::EchoRequest);
        echo_req_packet.set_icmp_code(pnet::packet::icmp::IcmpCode(0));
        echo_req_packet.set_identifier(self.icmp_identifier);
        echo_req_packet.set_sequence_number(sequence);

        // Create payload with identifier and sequence for validation
        let payload_data = (self.icmp_identifier as u32) << 16 | (sequence as u32);
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
        self.socket
            .send_to(echo_req_packet.packet(), dest_addr)
            .await
            .context("Failed to send ICMP packet")?;

        trace_time!(
            self.verbose,
            "Sent ICMP echo seq={} ttl={} to {} in {:?}",
            sequence,
            ttl,
            dest,
            send_start.elapsed()
        );

        Ok(())
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

        // Create oneshot channel for this probe
        let (tx, rx) = oneshot::channel();

        // Increment pending count
        {
            let mut count = self
                .pending_count
                .lock()
                .expect("Failed to lock pending_count");
            *count += 1;
        }

        // Store pending probe with the oneshot sender
        {
            let mut pending_probes = self.pending_probes.lock().await;
            pending_probes.insert(
                probe.sequence,
                PendingProbe {
                    probe_info: probe,
                    response_tx: tx,
                },
            );
        }

        // Send the ICMP echo request
        self.send_icmp_echo(dest_v4, probe.sequence, probe.ttl)
            .await?;

        // Wait for response with timeout
        let wait_start = Instant::now();
        match tokio::time::timeout(self.timing_config.socket_read_timeout, rx).await {
            Ok(Ok(response)) => {
                trace_time!(
                    self.verbose,
                    "Got response for seq={} in {:?}",
                    probe.sequence,
                    wait_start.elapsed()
                );
                Ok(response)
            }
            Ok(Err(_)) => {
                // Channel was dropped, shouldn't happen
                Err(anyhow!("Response channel closed unexpectedly"))
            }
            Err(_) => {
                trace_time!(
                    self.verbose,
                    "Timeout for seq={} after {:?}",
                    probe.sequence,
                    wait_start.elapsed()
                );
                // Timeout occurred
                // Remove from pending
                {
                    let mut pending_probes = self.pending_probes.lock().await;
                    pending_probes.remove(&probe.sequence);
                }

                // Decrement pending count
                {
                    let mut count = self
                        .pending_count
                        .lock()
                        .expect("Failed to lock pending_count");
                    *count = count.saturating_sub(1);
                }

                // Return timeout response
                Ok(ProbeResponse {
                    from_addr: dest,
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

    fn destination_reached(&self) -> bool {
        *self
            .destination_reached
            .lock()
            .expect("Failed to lock destination_reached")
    }

    fn pending_count(&self) -> usize {
        *self
            .pending_count
            .lock()
            .expect("Failed to lock pending_count")
    }
}

// Safety: The socket and shared state are properly synchronized
unsafe impl Send for MacOSAsyncIcmpSocket {}
unsafe impl Sync for MacOSAsyncIcmpSocket {}
