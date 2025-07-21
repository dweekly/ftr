//! IPv4 ICMP socket implementations

use super::{
    IpVersion, ProbeInfo, ProbeMode, ProbeProtocol, ProbeResponse, ProbeSocket, ResponseType,
    SocketMode,
};
use anyhow::{Context, Result};
use pnet::packet::icmp::echo_request::MutableEchoRequestPacket;
use pnet::packet::icmp::{echo_reply, IcmpPacket, IcmpTypes};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::Packet;
use pnet::util::checksum as pnet_checksum;
use socket2::Socket as Socket2;
use std::collections::HashMap;
use std::mem::MaybeUninit;
use std::net::{IpAddr, SocketAddr, SocketAddrV4};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Size of ICMP echo payload
const ICMP_ECHO_PAYLOAD_SIZE: usize = 16;
/// ICMP error header length in bytes
const ICMP_ERROR_HEADER_LEN_BYTES: usize = 8;
/// IPv4 header minimum length in bytes
const IPV4_HEADER_MIN_LEN_BYTES: usize = 20;

/// DGRAM ICMP socket for IPv4
pub struct DgramIcmpV4Socket {
    socket: Arc<Socket2>,
    mode: ProbeMode,
    icmp_identifier: u16,
    active_probes: Arc<Mutex<HashMap<u16, ProbeInfo>>>,
    destination_reached: Arc<Mutex<bool>>,
}

impl DgramIcmpV4Socket {
    /// Create a new DGRAM ICMP socket
    pub fn new(socket: Socket2) -> Result<Self> {
        // Set socket options
        socket.set_read_timeout(Some(Duration::from_millis(100)))?;

        let mode = ProbeMode {
            ip_version: IpVersion::V4,
            protocol: ProbeProtocol::Icmp,
            socket_mode: SocketMode::Dgram,
        };

        Ok(DgramIcmpV4Socket {
            socket: Arc::new(socket),
            mode,
            icmp_identifier: std::process::id() as u16,
            active_probes: Arc::new(Mutex::new(HashMap::new())),
            destination_reached: Arc::new(Mutex::new(false)),
        })
    }

    /// Parse an ICMP response
    fn parse_response(
        &self,
        packet_data: &[u8],
        from_addr: IpAddr,
        recv_time: Instant,
    ) -> Option<ProbeResponse> {
        // Parse outer IPv4 packet
        let outer_ipv4_packet = Ipv4Packet::new(packet_data)?;
        let icmp_data = outer_ipv4_packet.payload();
        let icmp_packet = IcmpPacket::new(icmp_data)?;

        let original_datagram_bytes = if icmp_data.len() >= ICMP_ERROR_HEADER_LEN_BYTES {
            &icmp_data[ICMP_ERROR_HEADER_LEN_BYTES..]
        } else {
            return None;
        };

        match icmp_packet.get_icmp_type() {
            IcmpTypes::TimeExceeded | IcmpTypes::DestinationUnreachable => {
                // Parse the original packet that triggered this response
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

                if original_type == IcmpTypes::EchoRequest.0 && original_id == self.icmp_identifier
                {
                    if let Some(probe_info) = self
                        .active_probes
                        .lock()
                        .expect("mutex poisoned")
                        .remove(&original_seq)
                    {
                        let response_type = match icmp_packet.get_icmp_type() {
                            IcmpTypes::TimeExceeded => ResponseType::TimeExceeded,
                            IcmpTypes::DestinationUnreachable => {
                                ResponseType::DestinationUnreachable(icmp_packet.get_icmp_code().0)
                            }
                            _ => unreachable!(),
                        };

                        let rtt = recv_time.duration_since(probe_info.sent_at);
                        return Some(ProbeResponse {
                            from_addr,
                            response_type,
                            probe_info,
                            rtt,
                        });
                    }
                }
            }
            IcmpTypes::EchoReply => {
                if let Some(echo_reply_pkt) = echo_reply::EchoReplyPacket::new(icmp_packet.packet())
                {
                    if echo_reply_pkt.get_identifier() == self.icmp_identifier {
                        if let Some(probe_info) = self
                            .active_probes
                            .lock()
                            .expect("mutex poisoned")
                            .remove(&echo_reply_pkt.get_sequence_number())
                        {
                            let rtt = recv_time.duration_since(probe_info.sent_at);
                            return Some(ProbeResponse {
                                from_addr,
                                response_type: ResponseType::EchoReply,
                                probe_info,
                                rtt,
                            });
                        }
                    }
                }
            }
            _ => {}
        }

        None
    }
}

impl ProbeSocket for DgramIcmpV4Socket {
    fn mode(&self) -> ProbeMode {
        self.mode
    }

    fn set_ttl(&self, ttl: u8) -> Result<()> {
        self.socket
            .set_ttl_v4(ttl as u32)
            .context("Failed to set TTL")?;
        Ok(())
    }

    fn send_probe(&self, target: IpAddr, probe_info: ProbeInfo) -> Result<()> {
        let target_v4 = match target {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(_) => {
                return Err(anyhow::anyhow!("IPv6 target not supported by IPv4 socket"))
            }
        };

        // Build ICMP Echo Request packet
        let mut icmp_buf =
            vec![0u8; MutableEchoRequestPacket::minimum_packet_size() + ICMP_ECHO_PAYLOAD_SIZE];
        let mut echo_req_packet = MutableEchoRequestPacket::new(&mut icmp_buf)
            .ok_or_else(|| anyhow::anyhow!("Failed to create ICMP packet"))?;

        echo_req_packet.set_icmp_type(IcmpTypes::EchoRequest);
        echo_req_packet.set_icmp_code(pnet::packet::icmp::IcmpCode(0));
        echo_req_packet.set_identifier(self.icmp_identifier);
        echo_req_packet.set_sequence_number(probe_info.sequence);

        // Create payload with identifier and sequence for validation
        let payload_data = (self.icmp_identifier as u32) << 16 | (probe_info.sequence as u32);
        let payload_bytes = payload_data.to_be_bytes();
        let mut final_payload = vec![0u8; ICMP_ECHO_PAYLOAD_SIZE];
        let bytes_to_copy = payload_bytes.len().min(ICMP_ECHO_PAYLOAD_SIZE);
        final_payload[..bytes_to_copy].copy_from_slice(&payload_bytes[..bytes_to_copy]);
        echo_req_packet.set_payload(&final_payload);

        // Calculate checksum
        let checksum = pnet_checksum(echo_req_packet.packet(), 1);
        echo_req_packet.set_checksum(checksum);

        // Send the packet
        let target_addr = SocketAddr::V4(SocketAddrV4::new(target_v4, 0));
        self.socket
            .send_to(echo_req_packet.packet(), &target_addr.into())
            .context("Failed to send ICMP packet")?;

        // Track the probe
        self.active_probes
            .lock()
            .expect("mutex poisoned")
            .insert(probe_info.sequence, probe_info);

        Ok(())
    }

    fn recv_response(&self, timeout: Duration) -> Result<Option<ProbeResponse>> {
        let mut recv_buf = [MaybeUninit::uninit(); 1500];
        let deadline = Instant::now() + timeout;

        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(None);
            }

            self.socket
                .set_read_timeout(Some(remaining.min(Duration::from_millis(100))))?;

            match self.socket.recv_from(&mut recv_buf) {
                Ok((size, socket_addr)) => {
                    let recv_time = Instant::now();
                    let from_addr = match socket_addr.as_socket_ipv4() {
                        Some(s) => IpAddr::V4(*s.ip()),
                        None => continue,
                    };

                    let initialized_part: &[MaybeUninit<u8>] = &recv_buf[..size];
                    let packet_data: &[u8] =
                        unsafe { &*(initialized_part as *const [MaybeUninit<u8>] as *const [u8]) };

                    if let Some(response) = self.parse_response(packet_data, from_addr, recv_time) {
                        // Check if destination reached
                        if matches!(
                            response.response_type,
                            ResponseType::EchoReply | ResponseType::DestinationUnreachable(_)
                        ) {
                            *self.destination_reached.lock().expect("mutex poisoned") = true;
                        }
                        return Ok(Some(response));
                    }
                }
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    continue;
                }
                Err(e) => return Err(e.into()),
            }
        }
    }

    fn destination_reached(&self) -> bool {
        *self.destination_reached.lock().expect("mutex poisoned")
    }
}

/// Raw ICMP socket for IPv4 (full IP packet control)
pub struct RawIcmpV4Socket {
    socket: Arc<Socket2>,
    mode: ProbeMode,
    icmp_identifier: u16,
    active_probes: Arc<Mutex<HashMap<u16, ProbeInfo>>>,
    destination_reached: Arc<Mutex<bool>>,
}

impl RawIcmpV4Socket {
    /// Create a new Raw ICMP socket
    pub fn new(socket: Socket2) -> Result<Self> {
        // Set socket options
        socket.set_read_timeout(Some(Duration::from_millis(100)))?;
        
        // Enable IP_HDRINCL to include IP header
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::io::AsRawFd;
            unsafe {
                let enable: i32 = 1;
                libc::setsockopt(
                    socket.as_raw_fd(),
                    libc::IPPROTO_IP,
                    libc::IP_HDRINCL,
                    &enable as *const _ as *const libc::c_void,
                    std::mem::size_of::<i32>() as libc::socklen_t,
                );
            }
        }
        
        let mode = ProbeMode {
            ip_version: IpVersion::V4,
            protocol: ProbeProtocol::Icmp,
            socket_mode: SocketMode::Raw,
        };

        Ok(RawIcmpV4Socket {
            socket: Arc::new(socket),
            mode,
            icmp_identifier: std::process::id() as u16,
            active_probes: Arc::new(Mutex::new(HashMap::new())),
            destination_reached: Arc::new(Mutex::new(false)),
        })
    }

    /// Build an IPv4 packet with ICMP payload
    fn build_ipv4_packet(&self, target: std::net::Ipv4Addr, ttl: u8, icmp_payload: &[u8]) -> Vec<u8> {
        use pnet::packet::ipv4::MutableIpv4Packet;
        use pnet::packet::ip::IpNextHeaderProtocols;
        
        let total_len = IPV4_HEADER_MIN_LEN_BYTES + icmp_payload.len();
        let mut packet = vec![0u8; total_len];
        
        if let Some(mut ipv4_packet) = MutableIpv4Packet::new(&mut packet) {
            ipv4_packet.set_version(4);
            ipv4_packet.set_header_length(5); // 5 * 4 = 20 bytes
            ipv4_packet.set_dscp(0);
            ipv4_packet.set_ecn(0);
            ipv4_packet.set_total_length(total_len as u16);
            ipv4_packet.set_identification(rand::random::<u16>());
            ipv4_packet.set_flags(0);
            ipv4_packet.set_fragment_offset(0);
            ipv4_packet.set_ttl(ttl);
            ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
            ipv4_packet.set_source(std::net::Ipv4Addr::UNSPECIFIED); // Let kernel fill this
            ipv4_packet.set_destination(target);
            
            // Copy ICMP payload
            ipv4_packet.set_payload(icmp_payload);
            
            // Calculate IP checksum
            let checksum = pnet::packet::ipv4::checksum(&ipv4_packet.to_immutable());
            ipv4_packet.set_checksum(checksum);
        }
        
        packet
    }

    /// Parse an ICMP response (same as DGRAM version)
    fn parse_response(&self, packet_data: &[u8], from_addr: IpAddr, recv_time: Instant) -> Option<ProbeResponse> {
        // For raw sockets, we receive the full IP packet
        let ipv4_packet = Ipv4Packet::new(packet_data)?;
        let icmp_data = ipv4_packet.payload();
        let icmp_packet = IcmpPacket::new(icmp_data)?;

        let original_datagram_bytes = if icmp_data.len() >= ICMP_ERROR_HEADER_LEN_BYTES {
            &icmp_data[ICMP_ERROR_HEADER_LEN_BYTES..]
        } else {
            return None;
        };

        match icmp_packet.get_icmp_type() {
            IcmpTypes::TimeExceeded | IcmpTypes::DestinationUnreachable => {
                // Parse the original packet that triggered this response
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
                let original_id = u16::from_be_bytes([original_icmp_bytes[4], original_icmp_bytes[5]]);
                let original_seq = u16::from_be_bytes([original_icmp_bytes[6], original_icmp_bytes[7]]);

                if original_type == IcmpTypes::EchoRequest.0 && original_id == self.icmp_identifier {
                    if let Some(probe_info) = self.active_probes.lock().unwrap().remove(&original_seq) {
                        let response_type = match icmp_packet.get_icmp_type() {
                            IcmpTypes::TimeExceeded => ResponseType::TimeExceeded,
                            IcmpTypes::DestinationUnreachable => {
                                ResponseType::DestinationUnreachable(icmp_packet.get_icmp_code().0)
                            }
                            _ => unreachable!(),
                        };

                        let rtt = recv_time.duration_since(probe_info.sent_at);
                        return Some(ProbeResponse {
                            from_addr,
                            response_type,
                            probe_info,
                            rtt,
                        });
                    }
                }
            }
            IcmpTypes::EchoReply => {
                if let Some(echo_reply_pkt) = echo_reply::EchoReplyPacket::new(icmp_packet.packet()) {
                    if echo_reply_pkt.get_identifier() == self.icmp_identifier {
                        if let Some(probe_info) = self.active_probes.lock().unwrap().remove(&echo_reply_pkt.get_sequence_number()) {
                            let rtt = recv_time.duration_since(probe_info.sent_at);
                            return Some(ProbeResponse {
                                from_addr,
                                response_type: ResponseType::EchoReply,
                                probe_info,
                                rtt,
                            });
                        }
                    }
                }
            }
            _ => {}
        }

        None
    }
}

impl ProbeSocket for RawIcmpV4Socket {
    fn mode(&self) -> ProbeMode {
        self.mode
    }

    fn set_ttl(&self, _ttl: u8) -> Result<()> {
        // For raw sockets, we'll set TTL in the IP header when sending
        // Store it for later use if needed
        Ok(())
    }

    fn send_probe(&self, target: IpAddr, probe_info: ProbeInfo) -> Result<()> {
        let target_v4 = match target {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(_) => return Err(anyhow::anyhow!("IPv6 target not supported by IPv4 socket")),
        };

        // Build ICMP Echo Request packet
        let mut icmp_buf = vec![0u8; MutableEchoRequestPacket::minimum_packet_size() + ICMP_ECHO_PAYLOAD_SIZE];
        let mut echo_req_packet = MutableEchoRequestPacket::new(&mut icmp_buf)
            .ok_or_else(|| anyhow::anyhow!("Failed to create ICMP packet"))?;
        
        echo_req_packet.set_icmp_type(IcmpTypes::EchoRequest);
        echo_req_packet.set_icmp_code(pnet::packet::icmp::IcmpCode(0));
        echo_req_packet.set_identifier(self.icmp_identifier);
        echo_req_packet.set_sequence_number(probe_info.sequence);
        
        // Create payload
        let payload_data = (self.icmp_identifier as u32) << 16 | (probe_info.sequence as u32);
        let payload_bytes = payload_data.to_be_bytes();
        let mut final_payload = vec![0u8; ICMP_ECHO_PAYLOAD_SIZE];
        let bytes_to_copy = payload_bytes.len().min(ICMP_ECHO_PAYLOAD_SIZE);
        final_payload[..bytes_to_copy].copy_from_slice(&payload_bytes[..bytes_to_copy]);
        echo_req_packet.set_payload(&final_payload);
        
        // Calculate checksum
        let checksum = pnet_checksum(echo_req_packet.packet(), 1);
        echo_req_packet.set_checksum(checksum);
        
        // Build full IP packet
        let ip_packet = self.build_ipv4_packet(target_v4, probe_info.ttl, echo_req_packet.packet());
        
        // Send the packet
        let target_addr = SocketAddr::V4(SocketAddrV4::new(target_v4, 0));
        self.socket.send_to(&ip_packet, &target_addr.into())
            .context("Failed to send raw ICMP packet")?;
        
        // Track the probe
        self.active_probes.lock().unwrap().insert(probe_info.sequence, probe_info);
        
        Ok(())
    }

    fn recv_response(&self, timeout: Duration) -> Result<Option<ProbeResponse>> {
        let mut recv_buf = [MaybeUninit::uninit(); 1500];
        let deadline = Instant::now() + timeout;
        
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(None);
            }
            
            self.socket.set_read_timeout(Some(remaining.min(Duration::from_millis(100))))?;
            
            match self.socket.recv_from(&mut recv_buf) {
                Ok((size, socket_addr)) => {
                    let recv_time = Instant::now();
                    let from_addr = match socket_addr.as_socket_ipv4() {
                        Some(s) => IpAddr::V4(*s.ip()),
                        None => continue,
                    };
                    
                    let initialized_part: &[MaybeUninit<u8>] = &recv_buf[..size];
                    let packet_data: &[u8] = unsafe { 
                        &*(initialized_part as *const [MaybeUninit<u8>] as *const [u8])
                    };
                    
                    if let Some(response) = self.parse_response(packet_data, from_addr, recv_time) {
                        // Check if destination reached
                        if matches!(response.response_type, ResponseType::EchoReply | ResponseType::DestinationUnreachable(_)) {
                            *self.destination_reached.lock().unwrap() = true;
                        }
                        return Ok(Some(response));
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock || 
                         e.kind() == std::io::ErrorKind::TimedOut => {
                    continue;
                }
                Err(e) => return Err(e.into()),
            }
        }
    }

    fn destination_reached(&self) -> bool {
        *self.destination_reached.lock().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dgram_icmp_mode() {
        // We can't actually create a socket in tests without permissions,
        // but we can test the mode reporting
        let expected_mode = ProbeMode {
            ip_version: IpVersion::V4,
            protocol: ProbeProtocol::Icmp,
            socket_mode: SocketMode::Dgram,
        };

        // Just verify the mode is constructed correctly
        assert_eq!(expected_mode.description(), "Datagram ICMP IPv4");
    }

    #[test]
    fn test_raw_icmp_mode() {
        let expected_mode = ProbeMode {
            ip_version: IpVersion::V4,
            protocol: ProbeProtocol::Icmp,
            socket_mode: SocketMode::Raw,
        };
        
        assert_eq!(expected_mode.description(), "Raw ICMP IPv4");
    }
}
