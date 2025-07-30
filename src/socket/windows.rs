//! Windows-specific socket implementations using Windows ICMP API

use std::collections::HashMap;
use std::ffi::c_void;
use std::io;
use std::mem;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::OnceLock;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Result;
use windows_sys::Win32::Foundation::{GetLastError, ERROR_INSUFFICIENT_BUFFER, HANDLE};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    IcmpCloseHandle, IcmpCreateFile, IcmpSendEcho, ICMP_ECHO_REPLY, IP_DEST_HOST_UNREACHABLE,
    IP_DEST_NET_UNREACHABLE, IP_DEST_PORT_UNREACHABLE, IP_DEST_PROT_UNREACHABLE,
    IP_OPTION_INFORMATION, IP_SUCCESS, IP_TTL_EXPIRED_TRANSIT,
};
use windows_sys::Win32::Networking::WinSock::{WSAStartup, WSADATA};

// Global flag to track if Winsock has been initialized
static WINSOCK_INIT: OnceLock<()> = OnceLock::new();

/// Initialize Winsock once for the entire process
fn ensure_winsock_initialized() -> io::Result<()> {
    WINSOCK_INIT.get_or_init(|| unsafe {
        let mut wsadata: WSADATA = std::mem::zeroed();
        let result = WSAStartup(0x0202, &mut wsadata);
        if result != 0 {
            // This should never happen in practice, but if it does, we can't continue
            eprintln!("FATAL: Failed to initialize Winsock: {}", result);
            std::process::exit(1);
        }
    });
    Ok(())
}

use crate::socket::{ProbeInfo, ProbeMode, ProbeResponse, ProbeSocket, ResponseType};

/// Size of ICMP echo payload
const ICMP_ECHO_PAYLOAD_SIZE: usize = 32;

/// Wrapper for HANDLE to make it Send + Sync
struct IcmpHandle(HANDLE);

unsafe impl Send for IcmpHandle {}
unsafe impl Sync for IcmpHandle {}

/// Windows ICMP socket using ICMP API
pub struct WindowsIcmpSocket {
    icmp_handle: IcmpHandle,
    mode: ProbeMode,
    destination_reached: Arc<Mutex<bool>>,
    current_ttl: Arc<Mutex<u8>>,
    pending_probes: Arc<Mutex<HashMap<u16, (ProbeInfo, Ipv4Addr)>>>,
}

impl WindowsIcmpSocket {
    /// Create a new Windows ICMP socket
    pub fn new() -> io::Result<Self> {
        // Ensure Winsock is initialized
        ensure_winsock_initialized()?;

        // Create ICMP handle
        let icmp_handle = unsafe { IcmpCreateFile() };
        if icmp_handle.is_null() {
            return Err(io::Error::last_os_error());
        }

        Ok(Self {
            icmp_handle: IcmpHandle(icmp_handle),
            mode: ProbeMode {
                protocol: crate::ProbeProtocol::Icmp,
                socket_mode: crate::SocketMode::Raw,
                ip_version: crate::socket::IpVersion::V4,
            },
            destination_reached: Arc::new(Mutex::new(false)),
            current_ttl: Arc::new(Mutex::new(1)),
            pending_probes: Arc::new(Mutex::new(HashMap::new())),
        })
    }
}

impl Drop for WindowsIcmpSocket {
    fn drop(&mut self) {
        if !self.icmp_handle.0.is_null() {
            unsafe {
                IcmpCloseHandle(self.icmp_handle.0);
            }
        }
    }
}

impl ProbeSocket for WindowsIcmpSocket {
    fn mode(&self) -> ProbeMode {
        self.mode
    }

    fn set_ttl(&self, ttl: u8) -> Result<()> {
        *self.current_ttl.lock().expect("mutex poisoned") = ttl;
        Ok(())
    }

    fn send_probe(&self, dest: IpAddr, probe_info: ProbeInfo) -> Result<()> {
        let target_v4 = match dest {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(_) => {
                return Err(anyhow::anyhow!("IPv6 target not supported by IPv4 socket"))
            }
        };

        // Store the probe info for later when we call recv_response
        self.pending_probes
            .lock()
            .expect("mutex poisoned")
            .insert(probe_info.sequence, (probe_info, target_v4));
        Ok(())
    }

    fn recv_response(&self, timeout: Duration) -> Result<Option<ProbeResponse>> {
        // Get the oldest pending probe
        let (probe_info, target) = {
            let mut pending = self.pending_probes.lock().expect("mutex poisoned");
            if pending.is_empty() {
                return Ok(None);
            }
            // Get the probe with the smallest sequence number
            let min_seq = *pending
                .keys()
                .min()
                .expect("pending probes should not be empty");
            pending
                .remove(&min_seq)
                .expect("min_seq should exist in pending probes")
        };

        // Create send data
        let send_data = [0u8; ICMP_ECHO_PAYLOAD_SIZE];

        // Create IP options for TTL
        let mut ip_options = IP_OPTION_INFORMATION {
            Ttl: probe_info.ttl,
            Tos: 0,
            Flags: 0,
            OptionsSize: 0,
            OptionsData: std::ptr::null_mut(),
        };

        // Create reply buffer
        let reply_size = mem::size_of::<ICMP_ECHO_REPLY>() + ICMP_ECHO_PAYLOAD_SIZE + 8;
        let mut reply_buffer = vec![0u8; reply_size];

        // Convert target address
        let dest_addr = u32::from_ne_bytes(target.octets());

        let send_start = Instant::now();

        // Send ICMP echo request and wait for reply
        let result = unsafe {
            IcmpSendEcho(
                self.icmp_handle.0,
                dest_addr,
                send_data.as_ptr() as *const c_void,
                send_data.len() as u16,
                &mut ip_options as *mut IP_OPTION_INFORMATION,
                reply_buffer.as_mut_ptr() as *mut c_void,
                reply_buffer.len() as u32,
                timeout.as_millis() as u32,
            )
        };

        if result == 0 {
            // Check for timeout or other errors
            let error = unsafe { GetLastError() };
            if error == ERROR_INSUFFICIENT_BUFFER {
                return Err(anyhow::anyhow!("Reply buffer too small"));
            }
            // Timeout or no response
            return Ok(None);
        }

        // Parse the reply
        let reply = unsafe { &*(reply_buffer.as_ptr() as *const ICMP_ECHO_REPLY) };
        let rtt = send_start.elapsed();

        // Convert reply address to IpAddr
        let from_addr = IpAddr::V4(Ipv4Addr::from(reply.Address.to_be()));

        // Determine response type based on status
        let response_type = match reply.Status {
            IP_SUCCESS => {
                // Check if this is our destination
                if from_addr == IpAddr::V4(target) {
                    *self.destination_reached.lock().expect("mutex poisoned") = true;
                }
                ResponseType::EchoReply
            }
            IP_TTL_EXPIRED_TRANSIT => ResponseType::TimeExceeded,
            IP_DEST_NET_UNREACHABLE => ResponseType::DestinationUnreachable(0),
            IP_DEST_HOST_UNREACHABLE => ResponseType::DestinationUnreachable(1),
            IP_DEST_PROT_UNREACHABLE => ResponseType::DestinationUnreachable(2),
            IP_DEST_PORT_UNREACHABLE => ResponseType::DestinationUnreachable(3),
            _ => return Ok(None), // Unknown response type
        };

        Ok(Some(ProbeResponse {
            from_addr,
            response_type,
            probe_info,
            rtt,
        }))
    }

    fn destination_reached(&self) -> bool {
        *self.destination_reached.lock().expect("mutex poisoned")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    #[cfg(target_os = "windows")]
    fn test_windows_icmp_socket_creation() {
        // Test that we can create a Windows ICMP socket
        let socket = WindowsIcmpSocket::new();
        assert!(socket.is_ok(), "Failed to create Windows ICMP socket");
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn test_windows_icmp_mode() {
        let socket = WindowsIcmpSocket::new().unwrap();
        let mode = socket.mode();
        assert_eq!(mode.protocol, crate::ProbeProtocol::Icmp);
        assert_eq!(mode.socket_mode, crate::SocketMode::Raw);
        assert_eq!(mode.ip_version, crate::socket::IpVersion::V4);
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn test_windows_icmp_set_ttl() {
        let socket = WindowsIcmpSocket::new().unwrap();
        assert!(socket.set_ttl(10).is_ok());
        assert!(socket.set_ttl(255).is_ok());
        assert!(socket.set_ttl(1).is_ok());
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn test_windows_icmp_send_probe() {
        let socket = WindowsIcmpSocket::new().unwrap();
        let target = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let probe_info = ProbeInfo {
            ttl: 1,
            identifier: 12345,
            sequence: 1,
            sent_at: Instant::now(),
        };

        // send_probe just stores the probe, doesn't actually send yet
        assert!(socket.send_probe(target, probe_info).is_ok());
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn test_windows_icmp_ipv6_error() {
        let socket = WindowsIcmpSocket::new().unwrap();
        let target = IpAddr::V6("::1".parse().unwrap());
        let probe_info = ProbeInfo {
            ttl: 1,
            identifier: 12345,
            sequence: 1,
            sent_at: Instant::now(),
        };

        let result = socket.send_probe(target, probe_info);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("IPv6"));
    }
}
