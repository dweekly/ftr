//! UDP socket implementation for traceroute

use super::{IpVersion, ProbeInfo, ProbeMode, ProbeProtocol, ProbeResponse, ProbeSocket, ResponseType, SocketMode};
use anyhow::{Context, Result};
use pnet::packet::icmp::{IcmpPacket, IcmpTypes};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::Packet;
use socket2::Socket as Socket2;
use std::collections::HashMap;
use std::mem::MaybeUninit;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use std::io::ErrorKind;

/// Base port for UDP traceroute (traditional traceroute port)
const UDP_BASE_PORT: u16 = 33434;

// Note: Basic UDP socket without ICMP is non-functional for traceroute
// Only UdpWithIcmpSocket below provides working UDP traceroute

/// UDP socket using IP_RECVERR on Linux (no root required)
#[cfg(target_os = "linux")]
pub struct UdpRecvErrSocket {
    socket: UdpSocket,
    mode: ProbeMode,
    active_probes: Arc<Mutex<HashMap<u16, ProbeInfo>>>,
    destination_reached: Arc<Mutex<bool>>,
    /// Maps port numbers to probe info for matching responses
    port_to_probe: Arc<Mutex<HashMap<u16, ProbeInfo>>>,
}

#[cfg(target_os = "linux")]
impl UdpRecvErrSocket {
    /// Create a new UDP socket with IP_RECVERR enabled
    pub fn new(socket: Socket2) -> Result<Self> {
        use std::os::unix::io::AsRawFd;
        
        // Enable IP_RECVERR to receive ICMP errors via MSG_ERRQUEUE
        unsafe {
            let enable: i32 = 1;
            let ret = libc::setsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_IP,
                libc::IP_RECVERR,
                &enable as *const _ as *const libc::c_void,
                std::mem::size_of::<i32>() as libc::socklen_t,
            );
            if ret != 0 {
                return Err(anyhow::anyhow!("Failed to set IP_RECVERR"));
            }
        }
        
        let socket: UdpSocket = socket.into();
        socket.set_nonblocking(true)?;

        let mode = ProbeMode {
            ip_version: IpVersion::V4,
            protocol: ProbeProtocol::Udp,
            socket_mode: SocketMode::Dgram,
        };

        Ok(UdpRecvErrSocket {
            socket,
            mode,
            active_probes: Arc::new(Mutex::new(HashMap::new())),
            destination_reached: Arc::new(Mutex::new(false)),
            port_to_probe: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// Get the destination port for a given TTL
    fn get_dest_port(ttl: u8) -> u16 {
        UDP_BASE_PORT + ttl as u16
    }
}

#[cfg(target_os = "linux")]
impl ProbeSocket for UdpRecvErrSocket {
    fn mode(&self) -> ProbeMode {
        self.mode
    }

    fn set_ttl(&self, ttl: u8) -> Result<()> {
        self.socket
            .set_ttl(ttl as u32)
            .context("Failed to set TTL")?;
        Ok(())
    }

    fn send_probe(&self, target: IpAddr, probe_info: ProbeInfo) -> Result<()> {
        // Calculate destination port based on TTL
        let dest_port = Self::get_dest_port(probe_info.ttl);
        let target_addr = SocketAddr::new(target, dest_port);
        
        // Create payload with identifier and sequence
        let mut payload = Vec::with_capacity(4);
        payload.extend_from_slice(&probe_info.identifier.to_be_bytes());
        payload.extend_from_slice(&probe_info.sequence.to_be_bytes());
        
        // Send UDP packet
        self.socket
            .send_to(&payload, target_addr)
            .context("Failed to send UDP packet")?;
        
        // Track the probe
        self.active_probes.lock().expect("mutex poisoned").insert(probe_info.sequence, probe_info.clone());
        self.port_to_probe.lock().expect("mutex poisoned").insert(dest_port, probe_info);
        
        Ok(())
    }

    fn recv_response(&self, timeout: Duration) -> Result<Option<ProbeResponse>> {
        use std::os::unix::io::AsRawFd;
        
        let deadline = Instant::now() + timeout;
        
        // We need to check the error queue for ICMP responses
        let mut buf = [0u8; 512];
        let mut control_buf = [0u8; 512];
        
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(None);
            }
            
            // Create msghdr for recvmsg with MSG_ERRQUEUE
            let mut iovec = libc::iovec {
                iov_base: buf.as_mut_ptr() as *mut libc::c_void,
                iov_len: buf.len(),
            };
            
            let mut msg = libc::msghdr {
                msg_name: std::ptr::null_mut(),
                msg_namelen: 0,
                msg_iov: &mut iovec,
                msg_iovlen: 1,
                msg_control: control_buf.as_mut_ptr() as *mut libc::c_void,
                msg_controllen: control_buf.len(),
                msg_flags: 0,
            };
            
            // Try to receive from error queue
            unsafe {
                let ret = libc::recvmsg(
                    self.socket.as_raw_fd(),
                    &mut msg,
                    libc::MSG_ERRQUEUE | libc::MSG_DONTWAIT
                );
                
                if ret > 0 {
                    // Parse the error message to extract ICMP info
                    // This is complex and requires parsing the ancillary data
                    // For now, we'll provide a placeholder
                    // TODO: Implement proper IP_RECVERR parsing
                    eprintln!("Received error queue message (parsing not yet implemented)");
                }
            }
            
            // Also check for regular responses (though we don't expect any)
            match self.socket.recv_from(&mut buf) {
                Ok((_, _)) => {
                    // Unexpected regular response
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // No data available, sleep briefly
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(_) => {}
            }
            
            if Instant::now() >= deadline {
                return Ok(None);
            }
        }
    }

    fn destination_reached(&self) -> bool {
        *self.destination_reached.lock().expect("mutex poisoned")
    }
}

/// UDP socket with raw ICMP receiver for full UDP traceroute support
pub struct UdpWithIcmpSocket {
    udp_socket: UdpSocket,
    icmp_socket: Option<Socket2>, // Raw socket for receiving ICMP
    mode: ProbeMode,
    active_probes: Arc<Mutex<HashMap<u16, ProbeInfo>>>,
    destination_reached: Arc<Mutex<bool>>,
    port_to_probe: Arc<Mutex<HashMap<u16, ProbeInfo>>>,
}

impl UdpWithIcmpSocket {
    /// Create a new UDP socket with optional ICMP receiver
    pub fn new(udp_socket: Socket2, icmp_socket: Option<Socket2>) -> Result<Self> {
        let udp_socket: UdpSocket = udp_socket.into();
        udp_socket.set_nonblocking(true)?;

        if let Some(ref icmp) = icmp_socket {
            icmp.set_nonblocking(true)?;
        }

        let mode = ProbeMode {
            ip_version: IpVersion::V4,
            protocol: ProbeProtocol::Udp,
            socket_mode: SocketMode::Dgram,
        };

        Ok(UdpWithIcmpSocket {
            udp_socket,
            icmp_socket,
            mode,
            active_probes: Arc::new(Mutex::new(HashMap::new())),
            destination_reached: Arc::new(Mutex::new(false)),
            port_to_probe: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    fn get_dest_port(ttl: u8) -> u16 {
        UDP_BASE_PORT + ttl as u16
    }

    /// Parse an ICMP response to our UDP probe
    fn parse_icmp_response(&self, packet_data: &[u8], from_addr: IpAddr, recv_time: Instant) -> Option<ProbeResponse> {
        // Constants for ICMP parsing
        const ICMP_ERROR_HEADER_LEN_BYTES: usize = 8;
        const IPV4_HEADER_MIN_LEN_BYTES: usize = 20;
        const UDP_HEADER_LEN_BYTES: usize = 8;

        // Parse outer IPv4 packet
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
                let original_udp_bytes = inner_ip_packet.payload();
                
                if original_udp_bytes.len() < UDP_HEADER_LEN_BYTES {
                    return None;
                }

                // Extract UDP port from original packet
                let dest_port = u16::from_be_bytes([original_udp_bytes[2], original_udp_bytes[3]]);
                
                // Match port to probe
                if let Some(probe_info) = self.port_to_probe.lock().expect("mutex poisoned").remove(&dest_port) {
                    // Also remove from active probes
                    self.active_probes.lock().expect("mutex poisoned").remove(&probe_info.sequence);
                    
                    let response_type = match icmp_packet.get_icmp_type() {
                        IcmpTypes::TimeExceeded => ResponseType::TimeExceeded,
                        IcmpTypes::DestinationUnreachable => {
                            let code = icmp_packet.get_icmp_code().0;
                            if code == 3 {
                                // Port unreachable - we've reached the destination
                                *self.destination_reached.lock().expect("mutex poisoned") = true;
                                ResponseType::UdpPortUnreachable
                            } else {
                                ResponseType::DestinationUnreachable(code)
                            }
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
            _ => {}
        }

        None
    }
}

impl ProbeSocket for UdpWithIcmpSocket {
    fn mode(&self) -> ProbeMode {
        self.mode
    }

    fn set_ttl(&self, ttl: u8) -> Result<()> {
        self.udp_socket
            .set_ttl(ttl as u32)
            .context("Failed to set TTL")?;
        Ok(())
    }

    fn send_probe(&self, target: IpAddr, probe_info: ProbeInfo) -> Result<()> {
        let dest_port = Self::get_dest_port(probe_info.ttl);
        let target_addr = SocketAddr::new(target, dest_port);

        // Create payload with identifier and sequence
        let mut payload = Vec::with_capacity(4);
        payload.extend_from_slice(&probe_info.identifier.to_be_bytes());
        payload.extend_from_slice(&probe_info.sequence.to_be_bytes());

        self.udp_socket
            .send_to(&payload, target_addr)
            .context("Failed to send UDP packet")?;

        self.active_probes
            .lock()
            .expect("mutex poisoned")
            .insert(probe_info.sequence, probe_info.clone());
        self.port_to_probe
            .lock()
            .expect("mutex poisoned")
            .insert(dest_port, probe_info);

        Ok(())
    }

    fn recv_response(&self, timeout: Duration) -> Result<Option<ProbeResponse>> {
        if let Some(ref icmp_socket) = self.icmp_socket {
            let mut recv_buf = [MaybeUninit::uninit(); 1500];
            let deadline = Instant::now() + timeout;
            
            loop {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Ok(None);
                }
                
                icmp_socket.set_read_timeout(Some(remaining.min(Duration::from_millis(100))))?;
                
                match icmp_socket.recv_from(&mut recv_buf) {
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
                        
                        if let Some(response) = self.parse_icmp_response(packet_data, from_addr, recv_time) {
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
        } else {
            // Fallback: Check for connection errors on the UDP socket
            let mut buf = [0u8; 1];
            match self.udp_socket.recv(&mut buf) {
                Err(e) if e.kind() == ErrorKind::ConnectionRefused => {
                    // This might indicate we reached the destination
                    *self.destination_reached.lock().expect("mutex poisoned") = true;
                }
                _ => {}
            }
            
            Ok(None)
        }
    }

    fn destination_reached(&self) -> bool {
        *self.destination_reached.lock().expect("mutex poisoned")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_udp_port_calculation() {
        assert_eq!(UdpWithIcmpSocket::get_dest_port(1), 33435);
        assert_eq!(UdpWithIcmpSocket::get_dest_port(10), 33444);
        assert_eq!(UdpWithIcmpSocket::get_dest_port(30), 33464);
    }

    #[test]
    fn test_udp_mode() {
        let expected_mode = ProbeMode {
            ip_version: IpVersion::V4,
            protocol: ProbeProtocol::Udp,
            socket_mode: SocketMode::Dgram,
        };

        assert_eq!(expected_mode.description(), "Datagram UDP IPv4");
    }
}