//! Windows IOCP-based ICMP socket implementation for immediate event notifications

use std::collections::HashMap;
use std::ffi::c_void;
use std::io;
use std::mem;
use std::net::{IpAddr, Ipv4Addr};
use std::ptr;
use std::sync::OnceLock;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::thread;

use anyhow::Result;
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_IO_PENDING, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    IcmpCloseHandle, IcmpCreateFile, IcmpSendEcho2, ICMP_ECHO_REPLY, IP_DEST_HOST_UNREACHABLE,
    IP_DEST_NET_UNREACHABLE, IP_DEST_PORT_UNREACHABLE, IP_DEST_PROT_UNREACHABLE,
    IP_OPTION_INFORMATION, IP_SUCCESS, IP_TTL_EXPIRED_TRANSIT,
};
use windows_sys::Win32::Networking::WinSock::{WSAStartup, WSADATA};
use windows_sys::Win32::System::IO::{
    CreateIoCompletionPort, GetQueuedCompletionStatus, PostQueuedCompletionStatus,
    OVERLAPPED,
};
use windows_sys::Win32::System::Threading::{CreateEventW};
use tokio::sync::mpsc;

use crate::socket::{ProbeInfo, ProbeMode, ProbeResponse, ProbeSocket, ResponseType};
use crate::debug_print;

// ICMP status codes not provided by windows-sys
const IP_REQ_TIMED_OUT: u32 = 11010;
const IP_GENERAL_FAILURE: u32 = 11050;

// Global flag to track if Winsock has been initialized
static WINSOCK_INIT: OnceLock<()> = OnceLock::new();

/// Initialize Winsock once for the entire process
fn ensure_winsock_initialized() -> io::Result<()> {
    WINSOCK_INIT.get_or_init(|| unsafe {
        let mut wsadata: WSADATA = std::mem::zeroed();
        let result = WSAStartup(0x0202, &mut wsadata);
        if result != 0 {
            eprintln!("FATAL: Failed to initialize Winsock: {}", result);
            std::process::exit(1);
        }
    });
    Ok(())
}

/// Size of ICMP echo payload
const ICMP_ECHO_PAYLOAD_SIZE: usize = 32;

/// Shutdown key for IOCP
const SHUTDOWN_KEY: usize = 0;

/// Wrapper for HANDLE to make it Send + Sync
struct SafeHandle(HANDLE);

unsafe impl Send for SafeHandle {}
unsafe impl Sync for SafeHandle {}

impl Drop for SafeHandle {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
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
    #[allow(dead_code)]
    event: SafeHandle,
    reply_buffer: Vec<u8>,
}

/// Windows IOCP-based ICMP socket
pub struct WindowsIocpIcmpSocket {
    icmp_handle: SafeHandle,
    iocp_handle: SafeHandle,
    mode: ProbeMode,
    destination_reached: Arc<Mutex<bool>>,
    pending_probes: Arc<Mutex<HashMap<usize, PendingProbe>>>,
    #[allow(dead_code)]
    response_tx: mpsc::UnboundedSender<ProbeResponse>,
    response_rx: Arc<Mutex<mpsc::UnboundedReceiver<ProbeResponse>>>,
    worker_thread: Option<thread::JoinHandle<()>>,
}

impl WindowsIocpIcmpSocket {
    /// Create a new Windows IOCP ICMP socket
    pub fn new() -> io::Result<Self> {
        Self::new_with_config(None)
    }

    /// Create a new Windows IOCP ICMP socket with timing configuration
    pub fn new_with_config(_timing_config: Option<&crate::TimingConfig>) -> io::Result<Self> {
        // Ensure Winsock is initialized
        ensure_winsock_initialized()?;

        // Create ICMP handle
        let icmp_handle = unsafe { IcmpCreateFile() };
        if icmp_handle.is_null() || icmp_handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }

        // Create I/O completion port
        let iocp_handle = unsafe {
            CreateIoCompletionPort(
                INVALID_HANDLE_VALUE,
                ptr::null_mut(),
                0,
                1, // Single thread for now
            )
        };
        if iocp_handle.is_null() || iocp_handle == INVALID_HANDLE_VALUE {
            unsafe { IcmpCloseHandle(icmp_handle); }
            return Err(io::Error::last_os_error());
        }

        let (response_tx, response_rx) = mpsc::unbounded_channel();
        let destination_reached = Arc::new(Mutex::new(false));
        let pending_probes = Arc::new(Mutex::new(HashMap::new()));

        // Wrap handles
        let iocp_handle = SafeHandle(iocp_handle);
        
        // Start IOCP worker thread - convert handle to usize for Send
        let iocp_handle_usize = iocp_handle.0 as usize;
        let dest_reached_clone = Arc::clone(&destination_reached);
        let pending_probes_clone = Arc::clone(&pending_probes);
        let tx_clone = response_tx.clone();
        
        let worker_thread = thread::spawn(move || {
            Self::iocp_worker_thread(
                iocp_handle_usize as HANDLE, 
                dest_reached_clone, 
                pending_probes_clone,
                tx_clone
            );
        });

        Ok(Self {
            icmp_handle: SafeHandle(icmp_handle),
            iocp_handle,
            mode: ProbeMode {
                protocol: crate::ProbeProtocol::Icmp,
                socket_mode: crate::SocketMode::Raw,
                ip_version: crate::socket::IpVersion::V4,
            },
            destination_reached,
            pending_probes,
            response_tx,
            response_rx: Arc::new(Mutex::new(response_rx)),
            worker_thread: Some(worker_thread),
        })
    }

    /// IOCP worker thread
    fn iocp_worker_thread(
        iocp_handle: HANDLE,
        destination_reached: Arc<Mutex<bool>>,
        pending_probes: Arc<Mutex<HashMap<usize, PendingProbe>>>,
        response_tx: mpsc::UnboundedSender<ProbeResponse>,
    ) {
        loop {
            let mut bytes_transferred: u32 = 0;
            let mut completion_key: usize = 0;
            let mut overlapped_ptr: *mut OVERLAPPED = ptr::null_mut();

            // Wait for completion event
            let result = unsafe {
                GetQueuedCompletionStatus(
                    iocp_handle,
                    &mut bytes_transferred,
                    &mut completion_key,
                    &mut overlapped_ptr,
                    u32::MAX, // Infinite timeout
                )
            };

            if result == 0 {
                let error = unsafe { GetLastError() };
                if overlapped_ptr.is_null() && completion_key == 0 {
                    // This can happen on shutdown
                    debug_print!(2, "GetQueuedCompletionStatus returned with no data, error={}", error);
                    continue;
                }
            }

            // Check for shutdown signal
            if completion_key == SHUTDOWN_KEY {
                break;
            }

            // Process event completion
            if completion_key != 0 {
                // The completion key is the event handle
                let pending_probe = {
                    let mut pending = pending_probes.lock().expect("mutex poisoned");
                    pending.remove(&completion_key)
                };

                if let Some(probe) = pending_probe {
                    debug_print!(2, "IOCP: Event signaled for probe seq={}", 
                        probe.probe_info.sequence);

                    // Process the response
                    if let Some(response) = Self::process_icmp_response(
                        &probe,
                        &destination_reached,
                    ) {
                        let _ = response_tx.send(response);
                    }
                }
            }
        }
    }

    /// Process ICMP response
    fn process_icmp_response(
        pending: &PendingProbe,
        destination_reached: &Arc<Mutex<bool>>,
    ) -> Option<ProbeResponse> {
        // Parse the reply
        let reply = unsafe { &*(pending.reply_buffer.as_ptr() as *const ICMP_ECHO_REPLY) };
        
        // Check for timeout or failure
        match reply.Status {
            IP_REQ_TIMED_OUT | IP_GENERAL_FAILURE => {
                debug_print!(2, "Probe seq={} timed out or failed, status={}", 
                    pending.probe_info.sequence, reply.Status);
                return None;
            }
            _ => {}
        }
        
        // Use the RTT provided by Windows ICMP API
        let rtt = match reply.Status {
            IP_SUCCESS | IP_TTL_EXPIRED_TRANSIT => {
                let rtt_ms = reply.RoundTripTime as u64;
                if rtt_ms == 0 {
                    Duration::from_micros(500)
                } else {
                    Duration::from_millis(rtt_ms)
                }
            }
            _ => Duration::from_millis(1),
        };

        // Convert reply address to IpAddr
        let from_addr = IpAddr::V4(Ipv4Addr::from(reply.Address.to_be()));

        // Determine response type based on status
        let response_type = match reply.Status {
            IP_SUCCESS => {
                if from_addr == IpAddr::V4(pending.target) {
                    *destination_reached.lock().expect("mutex poisoned") = true;
                }
                ResponseType::EchoReply
            }
            IP_TTL_EXPIRED_TRANSIT => ResponseType::TimeExceeded,
            IP_DEST_NET_UNREACHABLE => ResponseType::DestinationUnreachable(0),
            IP_DEST_HOST_UNREACHABLE => ResponseType::DestinationUnreachable(1),
            IP_DEST_PROT_UNREACHABLE => ResponseType::DestinationUnreachable(2),
            IP_DEST_PORT_UNREACHABLE => ResponseType::DestinationUnreachable(3),
            _ => {
                debug_print!(2, "Unknown response status {} for probe seq={}", 
                    reply.Status, pending.probe_info.sequence);
                return None;
            }
        };

        Some(ProbeResponse {
            from_addr,
            response_type,
            probe_info: pending.probe_info.clone(),
            rtt,
        })
    }
}

impl Drop for WindowsIocpIcmpSocket {
    fn drop(&mut self) {
        // Signal shutdown to worker thread
        unsafe {
            PostQueuedCompletionStatus(
                self.iocp_handle.0,
                0,
                SHUTDOWN_KEY,
                ptr::null_mut(),
            );
        }

        // Wait for worker thread to finish
        if let Some(thread) = self.worker_thread.take() {
            let _ = thread.join();
        }

        // Clean up any remaining pending probes
        let pending = self.pending_probes.lock().expect("mutex poisoned");
        drop(pending); // Explicitly drop to release events

        // Close ICMP handle
        if !self.icmp_handle.0.is_null() && self.icmp_handle.0 != INVALID_HANDLE_VALUE {
            unsafe {
                IcmpCloseHandle(self.icmp_handle.0);
            }
        }
    }
}

impl ProbeSocket for WindowsIocpIcmpSocket {
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
                return Err(anyhow::anyhow!("IPv6 is not supported on Windows ICMP"));
            }
        };

        // Create event for this probe
        let event = unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) };
        if event.is_null() || event == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error().into());
        }

        // Associate event with IOCP
        let result = unsafe {
            CreateIoCompletionPort(
                event,
                self.iocp_handle.0,
                event as usize, // Use event handle as completion key
                0,
            )
        };
        if result.is_null() {
            unsafe { CloseHandle(event); }
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

        // Create reply buffer
        let reply_size = mem::size_of::<ICMP_ECHO_REPLY>() + ICMP_ECHO_PAYLOAD_SIZE + 8;
        let mut reply_buffer = vec![0u8; reply_size];

        // Convert target address
        let dest_addr = u32::from_ne_bytes(target_v4.octets());

        // Send ICMP echo request
        let result = unsafe {
            IcmpSendEcho2(
                self.icmp_handle.0,
                event,
                None, // No APC routine
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
            debug_print!(2, "IcmpSendEcho2 returned 0 for TTL={}, seq={}, error={}", 
                probe_info.ttl, probe_info.sequence, error);
            if error != ERROR_IO_PENDING {
                unsafe { CloseHandle(event); }
                return Err(io::Error::from_raw_os_error(error as i32).into());
            }
        } else {
            debug_print!(2, "IcmpSendEcho2 succeeded immediately for TTL={}, seq={}", 
                probe_info.ttl, probe_info.sequence);
            // Even if it succeeded immediately, the event will be signaled
        }

        // Store pending probe
        let pending_probe = PendingProbe {
            probe_info,
            target: target_v4,
            event: SafeHandle(event),
            reply_buffer,
        };

        self.pending_probes
            .lock()
            .expect("mutex poisoned")
            .insert(event as usize, pending_probe);

        Ok(())
    }

    fn recv_response(&self, _timeout: Duration) -> Result<Option<ProbeResponse>> {
        // Try to receive from the channel
        let mut rx = self.response_rx.lock().expect("mutex poisoned");
        
        match rx.try_recv() {
            Ok(response) => {
                debug_print!(2, "Received response: from={:?}, TTL={}, seq={}, RTT={:?}", 
                    response.from_addr, response.probe_info.ttl, 
                    response.probe_info.sequence, response.rtt);
                Ok(Some(response))
            }
            Err(_) => Ok(None),
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

    #[test]
    #[cfg(target_os = "windows")]
    fn test_windows_iocp_icmp_socket_creation() {
        let socket = WindowsIocpIcmpSocket::new();
        assert!(socket.is_ok(), "Failed to create Windows IOCP ICMP socket");
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn test_windows_iocp_icmp_mode() {
        let socket = WindowsIocpIcmpSocket::new().unwrap();
        let mode = socket.mode();
        assert_eq!(mode.protocol, crate::ProbeProtocol::Icmp);
        assert_eq!(mode.socket_mode, crate::SocketMode::Raw);
        assert_eq!(mode.ip_version, crate::socket::IpVersion::V4);
    }
}