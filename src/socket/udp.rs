//! UDP socket implementation for traceroute

use super::{
    IpVersion, ProbeInfo, ProbeMode, ProbeProtocol, ProbeResponse, ProbeSocket, ResponseType,
    SocketMode,
};
use anyhow::{Context, Result};
use pnet::packet::icmp::{IcmpPacket, IcmpTypes};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::Packet;
use socket2::Socket as Socket2;
use std::collections::HashMap;
use std::io::ErrorKind;
use std::mem::MaybeUninit;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[cfg(target_os = "linux")]
use std::mem;

// Linux specific constants for IP_RECVERR
#[cfg(target_os = "linux")]
const SO_EE_ORIGIN_ICMP: u8 = 2;

// sock_extended_err structure from Linux
#[cfg(target_os = "linux")]
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

// const UDP_BASE_PORT: u16 = 33434; // Unused - using fixed port 443 instead

/// Alternative well-known ports that may work better through firewalls
pub const UDP_PORT_DNS: u16 = 53;
/// UDP port 443 (HTTPS/QUIC) - less likely to be filtered by routers
pub const UDP_PORT_HTTPS: u16 = 443;

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
    fn get_dest_port(_ttl: u8) -> u16 {
        // Use port 443 (HTTPS/QUIC) which is less likely to be filtered
        // Using the same port for all probes like system traceroute -p 443
        UDP_PORT_HTTPS
    }

    /// Parse IP_RECVERR error from control messages
    #[cfg(target_os = "linux")]
    fn parse_error_message(&self, msg: &libc::msghdr, recv_time: Instant) -> Option<ProbeResponse> {
        unsafe {
            let mut cmsg: *const libc::cmsghdr = libc::CMSG_FIRSTHDR(msg);

            while !cmsg.is_null() {
                let cmsg_ref = &*cmsg;

                // Looking for IP_RECVERR message
                if cmsg_ref.cmsg_level == libc::IPPROTO_IP && cmsg_ref.cmsg_type == libc::IP_RECVERR
                {
                    // Get pointer to the error structure
                    let err_ptr = libc::CMSG_DATA(cmsg) as *const SockExtendedErr;
                    let sock_err = &*err_ptr;

                    // Only interested in ICMP errors
                    if sock_err.ee_origin != SO_EE_ORIGIN_ICMP {
                        cmsg = libc::CMSG_NXTHDR(msg, cmsg);
                        continue;
                    }

                    // Get the offending address (follows the SockExtendedErr structure)
                    let addr_ptr = (err_ptr as *const u8).add(mem::size_of::<SockExtendedErr>())
                        as *const libc::sockaddr_in;
                    let offender_addr = &*addr_ptr;
                    let from_addr = IpAddr::V4(std::net::Ipv4Addr::from(u32::from_be(
                        offender_addr.sin_addr.s_addr,
                    )));

                    // For UDP traceroute with IP_RECVERR, the original packet is returned in the
                    // iovec buffer, not in the control message. Let's check the iovec data.

                    // The original packet should be in the iovec buffer
                    let packet_data = if (*msg).msg_iovlen > 0 && !(*msg).msg_iov.is_null() {
                        let iov = &*(*msg).msg_iov;
                        std::slice::from_raw_parts(iov.iov_base as *const u8, iov.iov_len.min(128))
                    } else {
                        &[]
                    };

                    // Validate it looks like an IP packet
                    if packet_data.len() >= 28 && (packet_data[0] >> 4) == 4 {
                        // Extract IP header length
                        let ip_header_len = ((packet_data[0] & 0x0F) as usize) * 4;

                        if packet_data.len() >= ip_header_len + 8 {
                            // Get UDP header
                            let udp_header = &packet_data[ip_header_len..];
                            let dest_port = u16::from_be_bytes([udp_header[2], udp_header[3]]);

                            // Look up the probe by port
                            let probe_info = self
                                .port_to_probe
                                .lock()
                                .expect("mutex poisoned")
                                .remove(&dest_port);

                            if let Some(probe_info) = probe_info {
                                // Also remove from active probes
                                self.active_probes
                                    .lock()
                                    .expect("mutex poisoned")
                                    .remove(&probe_info.sequence);

                                // Determine response type based on ICMP type/code
                                let response_type = match sock_err.ee_type {
                                    11 => ResponseType::TimeExceeded, // ICMP Time Exceeded
                                    3 => {
                                        // ICMP Destination Unreachable
                                        if sock_err.ee_code == 3 {
                                            // Port unreachable - we've reached the destination
                                            *self
                                                .destination_reached
                                                .lock()
                                                .expect("mutex poisoned") = true;
                                            ResponseType::UdpPortUnreachable
                                        } else {
                                            ResponseType::DestinationUnreachable(sock_err.ee_code)
                                        }
                                    }
                                    _ => ResponseType::DestinationUnreachable(sock_err.ee_code),
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
                    } else {
                        // Fallback: if only one probe is pending, assume it's for that one
                        let mut port_map = self.port_to_probe.lock().expect("mutex poisoned");
                        if port_map.len() == 1 {
                            let port = *port_map.keys().next().unwrap();
                            let probe_info = port_map.remove(&port).unwrap();
                            self.active_probes
                                .lock()
                                .expect("mutex poisoned")
                                .remove(&probe_info.sequence);

                            let response_type = match sock_err.ee_type {
                                11 => ResponseType::TimeExceeded,
                                3 => {
                                    if sock_err.ee_code == 3 {
                                        *self.destination_reached.lock().expect("mutex poisoned") =
                                            true;
                                        ResponseType::UdpPortUnreachable
                                    } else {
                                        ResponseType::DestinationUnreachable(sock_err.ee_code)
                                    }
                                }
                                _ => ResponseType::DestinationUnreachable(sock_err.ee_code),
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

                cmsg = libc::CMSG_NXTHDR(msg, cmsg);
            }
        }

        None
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

        // Clear any pending socket errors before sending
        // This is necessary because ICMP errors can leave the socket in an error state
        use std::os::unix::io::AsRawFd;
        unsafe {
            let mut error: libc::c_int = 0;
            let mut error_len: libc::socklen_t =
                std::mem::size_of::<libc::c_int>() as libc::socklen_t;
            libc::getsockopt(
                self.socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                &mut error as *mut _ as *mut libc::c_void,
                &mut error_len,
            );
            // Socket error cleared if needed
        }

        // Create payload with identifier and sequence
        let mut payload = Vec::with_capacity(32);
        payload.extend_from_slice(&probe_info.identifier.to_be_bytes());
        payload.extend_from_slice(&probe_info.sequence.to_be_bytes());
        // Add some padding to make packet bigger (some routers ignore tiny packets)
        payload.extend_from_slice(b"ftr-traceroute-probe-padding");

        // Send UDP packet
        self.socket
            .send_to(&payload, target_addr)
            .context("Failed to send UDP packet")?;

        // Track the probe
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
                    libc::MSG_ERRQUEUE | libc::MSG_DONTWAIT,
                );

                if ret > 0 {
                    let recv_time = Instant::now();
                    // Parse the error message
                    if let Some(response) = self.parse_error_message(&msg, recv_time) {
                        return Ok(Some(response));
                    }
                } else if ret < 0 {
                    // Clear any pending errors by reading them
                    let errno = std::io::Error::last_os_error();
                    if errno.raw_os_error() != Some(libc::EAGAIN) {
                        eprintln!("recvmsg error: {:?}", errno);
                    }
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

    fn get_dest_port(_ttl: u8) -> u16 {
        // Use port 443 (HTTPS/QUIC) which is less likely to be filtered
        UDP_PORT_HTTPS
    }

    /// Parse an ICMP response to our UDP probe
    fn parse_icmp_response(
        &self,
        packet_data: &[u8],
        from_addr: IpAddr,
        recv_time: Instant,
    ) -> Option<ProbeResponse> {
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
                if let Some(probe_info) = self
                    .port_to_probe
                    .lock()
                    .expect("mutex poisoned")
                    .remove(&dest_port)
                {
                    // Also remove from active probes
                    self.active_probes
                        .lock()
                        .expect("mutex poisoned")
                        .remove(&probe_info.sequence);

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
        let mut payload = Vec::with_capacity(32);
        payload.extend_from_slice(&probe_info.identifier.to_be_bytes());
        payload.extend_from_slice(&probe_info.sequence.to_be_bytes());
        // Add padding to match UdpRecvErrSocket
        payload.extend_from_slice(b"ftr-traceroute-probe-padding");

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

                        if let Some(response) =
                            self.parse_icmp_response(packet_data, from_addr, recv_time)
                        {
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
