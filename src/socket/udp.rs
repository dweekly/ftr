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
    mode: ProbeMode,
    /// Maps sequence number to (socket, probe_info) for each active probe
    active_probes: Arc<Mutex<HashMap<u16, (UdpSocket, ProbeInfo)>>>,
    destination_reached: Arc<Mutex<bool>>,
    /// The destination port to use for UDP probes
    dest_port: u16,
}

#[cfg(target_os = "linux")]
impl UdpRecvErrSocket {
    /// Create a new UDP socket with IP_RECVERR enabled
    pub fn new(_socket: Socket2, port: u16) -> Result<Self> {
        Self::new_with_config(_socket, port, None)
    }

    /// Create a new UDP socket with IP_RECVERR enabled and timing configuration
    pub fn new_with_config(_socket: Socket2, port: u16, _timing_config: Option<&crate::TimingConfig>) -> Result<Self> {
        // We don't store a single socket anymore - each probe will create its own
        let mode = ProbeMode {
            ip_version: IpVersion::V4,
            protocol: ProbeProtocol::Udp,
            socket_mode: SocketMode::Dgram,
        };

        Ok(UdpRecvErrSocket {
            mode,
            active_probes: Arc::new(Mutex::new(HashMap::new())),
            destination_reached: Arc::new(Mutex::new(false)),
            dest_port: port,
        })
    }

    /// Get the destination port for a given TTL
    fn get_dest_port(&self) -> u16 {
        self.dest_port
    }

    /// Parse IP_RECVERR error from control messages with known probe info
    #[cfg(target_os = "linux")]
    fn parse_error_message_with_probe(
        &self,
        msg: &libc::msghdr,
        recv_time: Instant,
        probe_info: ProbeInfo,
    ) -> Option<ProbeResponse> {
        unsafe {
            let mut cmsg: *const libc::cmsghdr = libc::CMSG_FIRSTHDR(msg);

            while !cmsg.is_null() {
                // Read the cmsghdr structure using read_unaligned to handle potential alignment issues
                let cmsg_data = std::ptr::read_unaligned(cmsg);

                // Looking for IP_RECVERR message
                if cmsg_data.cmsg_level == libc::IPPROTO_IP
                    && cmsg_data.cmsg_type == libc::IP_RECVERR
                {
                    // Get pointer to the error structure
                    let err_ptr = libc::CMSG_DATA(cmsg) as *const SockExtendedErr;
                    let sock_err = std::ptr::read_unaligned(err_ptr);

                    // Only interested in ICMP errors
                    if sock_err.ee_origin != SO_EE_ORIGIN_ICMP {
                        cmsg = libc::CMSG_NXTHDR(msg, cmsg);
                        continue;
                    }

                    // Get the offending address (follows the SockExtendedErr structure)
                    let addr_ptr = (err_ptr as *const u8).add(mem::size_of::<SockExtendedErr>())
                        as *const libc::sockaddr_in;
                    let offender_addr = std::ptr::read_unaligned(addr_ptr);
                    let from_addr = IpAddr::V4(std::net::Ipv4Addr::from(u32::from_be(
                        offender_addr.sin_addr.s_addr,
                    )));

                    // Determine response type based on ICMP type/code
                    let response_type = match sock_err.ee_type {
                        11 => ResponseType::TimeExceeded, // ICMP Time Exceeded
                        3 => {
                            // ICMP Destination Unreachable
                            if sock_err.ee_code == 3 {
                                // Port unreachable - we've reached the destination
                                *self.destination_reached.lock().expect("mutex poisoned") = true;
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

    fn set_ttl(&self, _ttl: u8) -> Result<()> {
        // TTL is set per-socket when we create it in send_probe
        Ok(())
    }

    fn send_probe(&self, target: IpAddr, probe_info: ProbeInfo) -> Result<()> {
        use socket2::{Domain, Protocol, Socket as Socket2, Type};
        use std::net::Ipv4Addr;
        use std::os::unix::io::AsRawFd;

        // Create a new socket for this probe
        let socket = Socket2::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
            .context("Failed to create UDP socket")?;

        // Bind to an ephemeral port (0 = let OS choose)
        let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
        socket
            .bind(&bind_addr.into())
            .context("Failed to bind UDP socket")?;

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

        // Convert to UdpSocket and set non-blocking
        let udp_socket: UdpSocket = socket.into();
        udp_socket.set_nonblocking(true)?;

        // Set TTL for this probe
        udp_socket
            .set_ttl(probe_info.ttl as u32)
            .context("Failed to set TTL")?;

        // Calculate destination port
        let dest_port = self.get_dest_port();
        let target_addr = SocketAddr::new(target, dest_port);

        // Connect the socket to the destination
        // This is important for IP_RECVERR to work correctly
        udp_socket
            .connect(target_addr)
            .context("Failed to connect UDP socket")?;

        // Create payload with identifier and sequence
        let mut payload = Vec::with_capacity(32);
        payload.extend_from_slice(&probe_info.identifier.to_be_bytes());
        payload.extend_from_slice(&probe_info.sequence.to_be_bytes());
        // Add some padding to make packet bigger (some routers ignore tiny packets)
        payload.extend_from_slice(b"ftr-traceroute-probe-padding");

        // Send UDP packet (no destination needed since we're connected)
        udp_socket
            .send(&payload)
            .context("Failed to send UDP packet")?;

        // Store the socket and probe info
        self.active_probes
            .lock()
            .expect("mutex poisoned")
            .insert(probe_info.sequence, (udp_socket, probe_info));

        Ok(())
    }

    fn recv_response(&self, timeout: Duration) -> Result<Option<ProbeResponse>> {
        use std::os::unix::io::AsRawFd;

        let deadline = Instant::now() + timeout;
        let mut buf = [0u8; 512];
        let mut control_buf = [0u8; 512];
        let mut _loop_count = 0;

        loop {
            _loop_count += 1;
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(None);
            }

            // Get all active sockets
            let sockets: Vec<(u16, UdpSocket, ProbeInfo)> = {
                let guard = self.active_probes.lock().expect("mutex poisoned");
                guard
                    .iter()
                    .map(|(seq, (socket, info))| {
                        (
                            *seq,
                            socket.try_clone().expect("failed to clone socket"),
                            info.clone(),
                        )
                    })
                    .collect()
            };

            // Check each socket for responses
            for (sequence, socket, probe_info) in sockets {
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
                        socket.as_raw_fd(),
                        &mut msg,
                        libc::MSG_ERRQUEUE | libc::MSG_DONTWAIT,
                    );

                    if ret >= 0 {
                        // ret can be 0 when there's no data in iovec but control messages are present
                        let recv_time = Instant::now();
                        // Parse the error message with the known probe info
                        if let Some(response) =
                            self.parse_error_message_with_probe(&msg, recv_time, probe_info.clone())
                        {
                            // Remove from active probes
                            self.active_probes
                                .lock()
                                .expect("mutex poisoned")
                                .remove(&sequence);
                            return Ok(Some(response));
                        }
                    } else if ret == -1 {
                        let errno = std::io::Error::last_os_error();
                        if errno.raw_os_error() == Some(libc::EAGAIN) {
                            // No error available on this socket, continue to next
                        }
                    }
                }
            }

            // Sleep briefly before next iteration using global config
            std::thread::sleep(crate::config::timing::udp_retry_delay());

            if Instant::now() >= deadline {
                return Ok(None);
            }
        }
    }

    fn destination_reached(&self) -> bool {
        *self.destination_reached.lock().expect("mutex poisoned")
    }
    
    fn set_timing_config(&mut self, _config: &crate::TimingConfig) -> Result<()> {
        // No-op since we use global config now
        Ok(())
    }
}

/// UDP socket with raw ICMP receiver for full UDP traceroute support
pub struct UdpWithIcmpSocket {
    icmp_socket: Option<Socket2>, // Raw socket for receiving ICMP
    mode: ProbeMode,
    /// Maps sequence number to (socket, probe_info) for each active probe
    active_probes: Arc<Mutex<HashMap<u16, (UdpSocket, ProbeInfo)>>>,
    destination_reached: Arc<Mutex<bool>>,
    /// The destination port to use for UDP probes
    dest_port: u16,
}

impl UdpWithIcmpSocket {
    /// Create a new UDP socket with optional ICMP receiver
    pub fn new(_udp_socket: Socket2, icmp_socket: Option<Socket2>, port: u16) -> Result<Self> {
        Self::new_with_config(_udp_socket, icmp_socket, port, None)
    }

    /// Create a new UDP socket with optional ICMP receiver and timing configuration
    pub fn new_with_config(_udp_socket: Socket2, icmp_socket: Option<Socket2>, port: u16, _timing_config: Option<&crate::TimingConfig>) -> Result<Self> {
        // We don't store the UDP socket anymore - each probe will create its own
        if let Some(ref icmp) = icmp_socket {
            icmp.set_nonblocking(true)?;
        }

        let mode = ProbeMode {
            ip_version: IpVersion::V4,
            protocol: ProbeProtocol::Udp,
            socket_mode: SocketMode::Dgram,
        };

        Ok(UdpWithIcmpSocket {
            icmp_socket,
            mode,
            active_probes: Arc::new(Mutex::new(HashMap::new())),
            destination_reached: Arc::new(Mutex::new(false)),
            dest_port: port,
        })
    }

    fn get_dest_port(&self) -> u16 {
        self.dest_port
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
                let _dest_port = u16::from_be_bytes([original_udp_bytes[2], original_udp_bytes[3]]);

                // Try to extract identifier and sequence from UDP payload
                if original_udp_bytes.len() >= UDP_HEADER_LEN_BYTES + 4 {
                    // Our payload starts after UDP header
                    let udp_payload = &original_udp_bytes[UDP_HEADER_LEN_BYTES..];
                    if udp_payload.len() >= 4 {
                        // Extract identifier and sequence from our payload
                        let identifier = u16::from_be_bytes([udp_payload[0], udp_payload[1]]);
                        let sequence = u16::from_be_bytes([udp_payload[2], udp_payload[3]]);

                        // Look up by sequence
                        if let Some((_, probe_info)) = self
                            .active_probes
                            .lock()
                            .expect("mutex poisoned")
                            .remove(&sequence)
                        {
                            if probe_info.identifier == identifier {
                                // Valid match
                                let response_type = match icmp_packet.get_icmp_type() {
                                    IcmpTypes::TimeExceeded => ResponseType::TimeExceeded,
                                    IcmpTypes::DestinationUnreachable => {
                                        let code = icmp_packet.get_icmp_code().0;
                                        if code == 3 {
                                            // Port unreachable - we've reached the destination
                                            *self
                                                .destination_reached
                                                .lock()
                                                .expect("mutex poisoned") = true;
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
                    }
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

    fn set_ttl(&self, _ttl: u8) -> Result<()> {
        // TTL is set per-socket when we create it in send_probe
        Ok(())
    }

    fn send_probe(&self, target: IpAddr, probe_info: ProbeInfo) -> Result<()> {
        use socket2::{Domain, Protocol, Socket as Socket2, Type};
        use std::net::Ipv4Addr;

        // Create a new socket for this probe
        let socket = Socket2::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
            .context("Failed to create UDP socket")?;

        // Bind to an ephemeral port (0 = let OS choose)
        let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
        socket
            .bind(&bind_addr.into())
            .context("Failed to bind UDP socket")?;

        // Convert to UdpSocket and set non-blocking
        let udp_socket: UdpSocket = socket.into();
        udp_socket.set_nonblocking(true)?;

        // Set TTL for this probe
        udp_socket
            .set_ttl(probe_info.ttl as u32)
            .context("Failed to set TTL")?;

        // Calculate destination port
        let dest_port = self.get_dest_port();
        let target_addr = SocketAddr::new(target, dest_port);

        // Connect the socket to the destination
        udp_socket
            .connect(target_addr)
            .context("Failed to connect UDP socket")?;

        // Create payload with identifier and sequence
        let mut payload = Vec::with_capacity(32);
        payload.extend_from_slice(&probe_info.identifier.to_be_bytes());
        payload.extend_from_slice(&probe_info.sequence.to_be_bytes());
        // Add padding to match UdpRecvErrSocket
        payload.extend_from_slice(b"ftr-traceroute-probe-padding");

        udp_socket
            .send(&payload)
            .context("Failed to send UDP packet")?;

        // Store the socket and probe info
        self.active_probes
            .lock()
            .expect("mutex poisoned")
            .insert(probe_info.sequence, (udp_socket, probe_info));

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

                icmp_socket.set_read_timeout(Some(remaining.min(crate::config::timing::socket_read_timeout())))?;

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
            // Without ICMP socket, we can't receive responses
            Ok(None)
        }
    }

    fn destination_reached(&self) -> bool {
        *self.destination_reached.lock().expect("mutex poisoned")
    }
    
    fn set_timing_config(&mut self, _config: &crate::TimingConfig) -> Result<()> {
        // No-op since we use global config now
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use socket2::{Domain, Protocol, Socket as Socket2, Type};

    #[test]
    fn test_udp_port_configuration() {
        // Test that we can create sockets with different ports
        let socket1 = Socket2::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).unwrap();
        let socket2 = Socket2::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).unwrap();

        let udp_socket1 = UdpWithIcmpSocket::new_with_config(socket1, None, 53, None).unwrap();
        let udp_socket2 = UdpWithIcmpSocket::new(socket2, None, 443).unwrap();

        assert_eq!(udp_socket1.get_dest_port(), 53);
        assert_eq!(udp_socket2.get_dest_port(), 443);
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
