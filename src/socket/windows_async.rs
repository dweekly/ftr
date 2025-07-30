//! Windows-specific async socket implementation using IcmpSendEcho2

use std::collections::HashMap;
use std::ffi::c_void;
use std::io;
use std::mem;
use std::net::{IpAddr, Ipv4Addr};
use std::ptr;
use std::sync::OnceLock;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Result;
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_IO_PENDING, HANDLE, WAIT_OBJECT_0,
};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    IcmpCloseHandle, IcmpCreateFile, IcmpSendEcho2, ICMP_ECHO_REPLY, IP_DEST_HOST_UNREACHABLE,
    IP_DEST_NET_UNREACHABLE, IP_DEST_PORT_UNREACHABLE, IP_DEST_PROT_UNREACHABLE,
    IP_OPTION_INFORMATION, IP_SUCCESS, IP_TTL_EXPIRED_TRANSIT,
};
use windows_sys::Win32::Networking::WinSock::{WSAStartup, WSADATA};
use windows_sys::Win32::System::Threading::{CreateEventW, WaitForMultipleObjects};

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

/// Maximum concurrent probes
const MAX_CONCURRENT_PROBES: usize = 64;

/// Wrapper for HANDLE to make it Send + Sync
struct SafeHandle(HANDLE);

unsafe impl Send for SafeHandle {}
unsafe impl Sync for SafeHandle {}

impl Drop for SafeHandle {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != usize::MAX as HANDLE {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

/// Pending probe information
struct PendingProbe {
    probe_info: ProbeInfo,
    target: Ipv4Addr,
    event: SafeHandle,
    reply_buffer: Vec<u8>,
}

/// Windows async ICMP socket using IcmpSendEcho2 API
pub struct WindowsAsyncIcmpSocket {
    icmp_handle: SafeHandle,
    mode: ProbeMode,
    destination_reached: Arc<Mutex<bool>>,
    pending_probes: Arc<Mutex<HashMap<usize, PendingProbe>>>,
}

impl WindowsAsyncIcmpSocket {
    /// Create a new Windows async ICMP socket
    pub fn new() -> io::Result<Self> {
        Self::new_with_config(None)
    }

    /// Create a new Windows async ICMP socket with timing configuration
    pub fn new_with_config(_timing_config: Option<&crate::TimingConfig>) -> io::Result<Self> {
        // Ensure Winsock is initialized
        ensure_winsock_initialized()?;

        // Create ICMP handle
        let icmp_handle = unsafe { IcmpCreateFile() };
        if icmp_handle.is_null() || icmp_handle == usize::MAX as HANDLE {
            return Err(io::Error::last_os_error());
        }

        Ok(Self {
            icmp_handle: SafeHandle(icmp_handle),
            mode: ProbeMode {
                protocol: crate::ProbeProtocol::Icmp,
                socket_mode: crate::SocketMode::Raw,
                ip_version: crate::socket::IpVersion::V4,
            },
            destination_reached: Arc::new(Mutex::new(false)),
            pending_probes: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// Process completed probe
    fn process_completed_probe(&self, pending: PendingProbe) -> Result<Option<ProbeResponse>> {
        // Parse the reply
        let reply = unsafe { &*(pending.reply_buffer.as_ptr() as *const ICMP_ECHO_REPLY) };
        
        // Use the RTT provided by Windows ICMP API (in milliseconds)
        // The API provides valid RTT for both successful replies and TTL expired
        // Only use elapsed time for actual failures (unreachable, etc.)
        let rtt = match reply.Status {
            IP_SUCCESS | IP_TTL_EXPIRED_TRANSIT => {
                let rtt_ms = reply.RoundTripTime as u64;
                if rtt_ms == 0 {
                    // 0 can mean sub-millisecond response for successful requests
                    // For TTL expired, it shouldn't be 0, but handle it anyway
                    Duration::from_micros(500)
                } else {
                    Duration::from_millis(rtt_ms)
                }
            }
            _ => {
                // For actual failures (unreachable, etc.), the RTT isn't meaningful
                // Use a nominal value
                Duration::from_millis(1)
            }
        };

        // Convert reply address to IpAddr
        let from_addr = IpAddr::V4(Ipv4Addr::from(reply.Address.to_be()));

        // Determine response type based on status
        let response_type = match reply.Status {
            IP_SUCCESS => {
                // Check if this is our destination
                if from_addr == IpAddr::V4(pending.target) {
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
            probe_info: pending.probe_info,
            rtt,
        }))
    }
}

impl Drop for WindowsAsyncIcmpSocket {
    fn drop(&mut self) {
        if !self.icmp_handle.0.is_null() && self.icmp_handle.0 != usize::MAX as HANDLE {
            unsafe {
                IcmpCloseHandle(self.icmp_handle.0);
            }
        }
    }
}

impl ProbeSocket for WindowsAsyncIcmpSocket {
    fn mode(&self) -> ProbeMode {
        self.mode
    }

    fn set_ttl(&self, _ttl: u8) -> Result<()> {
        // TTL is set per probe in send_probe
        Ok(())
    }

    fn send_probe(&self, dest: IpAddr, probe_info: ProbeInfo) -> Result<()> {
        let target_v4 = match dest {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(_) => {
                return Err(anyhow::anyhow!("IPv6 target not supported by IPv4 socket"))
            }
        };

        // Check if we have too many pending probes
        {
            let pending = self.pending_probes.lock().expect("mutex poisoned");
            if pending.len() >= MAX_CONCURRENT_PROBES {
                return Err(anyhow::anyhow!("Too many pending probes"));
            }
        }

        // Create event for async notification
        let event = unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) };
        if event.is_null() || event == usize::MAX as HANDLE {
            return Err(io::Error::last_os_error().into());
        }

        // Create send data
        let send_data = [0u8; ICMP_ECHO_PAYLOAD_SIZE];

        // Create IP options for TTL
        let mut ip_options = IP_OPTION_INFORMATION {
            Ttl: probe_info.ttl,
            Tos: 0,
            Flags: 0,
            OptionsSize: 0,
            OptionsData: ptr::null_mut(),
        };

        // Create reply buffer - must be pinned in memory for async operation
        let reply_size = mem::size_of::<ICMP_ECHO_REPLY>() + ICMP_ECHO_PAYLOAD_SIZE + 8;
        let mut reply_buffer = vec![0u8; reply_size];

        // Convert target address
        let dest_addr = u32::from_ne_bytes(target_v4.octets());

        // Send ICMP echo request asynchronously - this returns immediately
        let result = unsafe {
            IcmpSendEcho2(
                self.icmp_handle.0,
                event,
                None,        // No APC routine
                ptr::null(), // No APC context
                dest_addr,
                send_data.as_ptr() as *const c_void,
                send_data.len() as u16,
                &mut ip_options as *mut IP_OPTION_INFORMATION,
                reply_buffer.as_mut_ptr() as *mut c_void,
                reply_size as u32,
                crate::config::timing::socket_read_timeout().as_millis() as u32,
            )
        };

        if result == 0 {
            let error = unsafe { GetLastError() };
            if error != ERROR_IO_PENDING {
                return Err(io::Error::from_raw_os_error(error as i32).into());
            }
        }

        // Store pending probe info AFTER the async send
        let pending_probe = PendingProbe {
            probe_info,
            target: target_v4,
            event: SafeHandle(event),
            reply_buffer,
        };

        // Store the pending probe with event handle as key
        self.pending_probes
            .lock()
            .expect("mutex poisoned")
            .insert(event as usize, pending_probe);

        Ok(())
    }

    fn recv_response(&self, timeout: Duration) -> Result<Option<ProbeResponse>> {
        let timeout_ms = timeout.as_millis() as u32;

        // Get all pending event handles
        let events: Vec<(usize, HANDLE)> = {
            let pending = self.pending_probes.lock().expect("mutex poisoned");
            if pending.is_empty() {
                return Ok(None);
            }
            pending.iter().map(|(k, v)| (*k, v.event.0)).collect()
        };

        if events.is_empty() {
            return Ok(None);
        }

        // Wait for ANY event to complete with WaitForMultipleObjects
        // This is much more efficient than polling
        let handles: Vec<HANDLE> = events.iter().map(|(_, h)| *h).collect();

        if !handles.is_empty() {
            // We can only wait for up to 64 handles at once
            let handles_to_wait = handles.len().min(64);
            let wait_handles = &handles[..handles_to_wait];

            // Use WaitForMultipleObjects to wait for ANY event
            let wait_result = unsafe {
                WaitForMultipleObjects(
                    handles_to_wait as u32,
                    wait_handles.as_ptr(),
                    0, // Wait for ANY object (not all)
                    timeout_ms,
                )
            };

            // Check if any event was signaled
            if wait_result < WAIT_OBJECT_0 + handles_to_wait as u32 {
                let index = (wait_result - WAIT_OBJECT_0) as usize;
                let (key, _) = events[index];

                // This probe completed
                let pending_probe = {
                    let mut pending = self.pending_probes.lock().expect("mutex poisoned");
                    pending.remove(&key)
                };

                if let Some(probe) = pending_probe {
                    return self.process_completed_probe(probe);
                }
            }
        }

        Ok(None)
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

    #[test]
    #[cfg(target_os = "windows")]
    fn test_windows_async_icmp_socket_creation() {
        let socket = WindowsAsyncIcmpSocket::new();
        assert!(socket.is_ok(), "Failed to create Windows async ICMP socket");
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn test_windows_async_icmp_mode() {
        let socket = WindowsAsyncIcmpSocket::new().unwrap();
        let mode = socket.mode();
        assert_eq!(mode.protocol, crate::ProbeProtocol::Icmp);
        assert_eq!(mode.socket_mode, crate::SocketMode::Raw);
        assert_eq!(mode.ip_version, crate::socket::IpVersion::V4);
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn test_windows_async_icmp_ipv6_error() {
        let socket = WindowsAsyncIcmpSocket::new().unwrap();
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
