//! UDP socket implementation for traceroute

use super::{IpVersion, ProbeInfo, ProbeMode, ProbeProtocol, ProbeResponse, ProbeSocket, SocketMode};
use anyhow::{Context, Result};
use socket2::Socket as Socket2;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use std::io::ErrorKind;

/// Base port for UDP traceroute (traditional traceroute port)
const UDP_BASE_PORT: u16 = 33434;

/// UDP socket for traceroute
pub struct UdpProbeSocket {
    socket: UdpSocket,
    mode: ProbeMode,
    active_probes: Arc<Mutex<HashMap<u16, ProbeInfo>>>,
    destination_reached: Arc<Mutex<bool>>,
    /// Maps port numbers to probe info for matching responses
    port_to_probe: Arc<Mutex<HashMap<u16, ProbeInfo>>>,
}

impl UdpProbeSocket {
    /// Create a new UDP probe socket
    pub fn new(socket: Socket2) -> Result<Self> {
        // Convert to standard UdpSocket for easier use
        let socket: UdpSocket = socket.into();
        socket.set_nonblocking(true)?;
        
        let mode = ProbeMode {
            ip_version: IpVersion::V4, // TODO: detect from socket
            protocol: ProbeProtocol::Udp,
            socket_mode: SocketMode::Dgram,
        };

        Ok(UdpProbeSocket {
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

impl ProbeSocket for UdpProbeSocket {
    fn mode(&self) -> ProbeMode {
        self.mode
    }

    fn set_ttl(&self, ttl: u8) -> Result<()> {
        self.socket.set_ttl(ttl as u32)
            .context("Failed to set TTL")?;
        Ok(())
    }

    fn send_probe(&self, target: IpAddr, probe_info: ProbeInfo) -> Result<()> {
        // Calculate destination port based on TTL
        let dest_port = Self::get_dest_port(probe_info.ttl);
        let target_addr = SocketAddr::new(target, dest_port);
        
        // Create a simple payload with probe identifier
        let payload = probe_info.identifier.to_be_bytes();
        
        // Send UDP packet
        self.socket.send_to(&payload, target_addr)
            .context("Failed to send UDP packet")?;
        
        // Track the probe by both sequence and port
        self.active_probes.lock().unwrap().insert(probe_info.sequence, probe_info.clone());
        self.port_to_probe.lock().unwrap().insert(dest_port, probe_info);
        
        Ok(())
    }

    fn recv_response(&self, timeout: Duration) -> Result<Option<ProbeResponse>> {
        let deadline = Instant::now() + timeout;
        
        // For UDP traceroute, we expect ICMP Port Unreachable responses
        // In this basic implementation, we'll try to use connected sockets
        // to detect errors via socket errors
        
        // Check if any active probes have timed out
        let now = Instant::now();
        let mut active_probes = self.active_probes.lock().unwrap();
        let mut timed_out = Vec::new();
        
        for (seq, probe) in active_probes.iter() {
            if now.duration_since(probe.sent_at) > timeout {
                timed_out.push(*seq);
            }
        }
        
        for seq in timed_out {
            active_probes.remove(&seq);
        }
        
        // In a real implementation, we would need a raw socket to receive ICMP messages
        // For now, we'll simulate timeout behavior
        if Instant::now() >= deadline {
            return Ok(None);
        }
        
        // Sleep briefly to avoid busy waiting
        std::thread::sleep(Duration::from_millis(10));
        
        Ok(None)
    }

    fn destination_reached(&self) -> bool {
        *self.destination_reached.lock().unwrap()
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
}

impl ProbeSocket for UdpWithIcmpSocket {
    fn mode(&self) -> ProbeMode {
        self.mode
    }

    fn set_ttl(&self, ttl: u8) -> Result<()> {
        self.udp_socket.set_ttl(ttl as u32)
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
        
        self.udp_socket.send_to(&payload, target_addr)
            .context("Failed to send UDP packet")?;
        
        self.active_probes.lock().unwrap().insert(probe_info.sequence, probe_info.clone());
        self.port_to_probe.lock().unwrap().insert(dest_port, probe_info);
        
        Ok(())
    }

    fn recv_response(&self, timeout: Duration) -> Result<Option<ProbeResponse>> {
        if let Some(ref icmp_socket) = self.icmp_socket {
            // TODO: Implement ICMP parsing for UDP responses
            // This would parse ICMP Port Unreachable messages
            // and match them to our sent probes
            
            // For now, return None
            let _ = (icmp_socket, timeout);
        }
        
        // Check for connection errors on the UDP socket
        // This can sometimes indicate destination unreachable
        let mut buf = [0u8; 1];
        match self.udp_socket.recv(&mut buf) {
            Err(e) if e.kind() == ErrorKind::ConnectionRefused => {
                // This might indicate we reached the destination
                *self.destination_reached.lock().unwrap() = true;
            }
            _ => {}
        }
        
        Ok(None)
    }

    fn destination_reached(&self) -> bool {
        *self.destination_reached.lock().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_udp_port_calculation() {
        assert_eq!(UdpProbeSocket::get_dest_port(1), 33435);
        assert_eq!(UdpProbeSocket::get_dest_port(10), 33444);
        assert_eq!(UdpProbeSocket::get_dest_port(30), 33464);
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