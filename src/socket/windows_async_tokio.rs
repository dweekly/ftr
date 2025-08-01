//! Windows async ICMP socket using Tokio
//!
//! This module implements an async ICMP socket for Windows using the
//! IcmpSendEcho2 API with Tokio's async primitives for immediate
//! response notification.

use crate::probe::{ProbeInfo, ProbeResponse};
use crate::socket::async_trait::{AsyncProbeSocket, ProbeMode};
use crate::TimingConfig;
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use std::ffi::c_void;
use std::mem;
use std::net::{IpAddr, Ipv4Addr};
use std::ptr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::oneshot;
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_IO_PENDING, HANDLE, WAIT_OBJECT_0,
};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    IcmpCloseHandle, IcmpCreateFile, IcmpSendEcho2, ICMP_ECHO_REPLY, IP_OPTION_INFORMATION,
    IP_SUCCESS,
};

// ICMP status codes not provided by windows-sys
const IP_REQ_TIMED_OUT: u32 = 11010;
const IP_GENERAL_FAILURE: u32 = 11050;
use windows_sys::Win32::System::Threading::{CreateEventW, WaitForSingleObject};

/// Windows async ICMP socket implementation
/// 
/// This uses the Windows IcmpSendEcho2 API for sending ICMP echo requests.
/// 
/// # Implementation Notes
/// 
/// ## Timeout Handling
/// 
/// Windows ICMP API has specific requirements for reliable timeout handling:
/// 
/// - **Minimum Timeout**: Through empirical testing, we found that timeouts < 30ms
///   produce inconsistent results where probes may not return any response even
///   from low-latency hosts. This appears to be a limitation of the Windows ICMP
///   implementation.
/// 
/// - **Timeout Buffer**: We give Windows a longer timeout than our Tokio timeout
///   (user timeout + 50ms buffer) to ensure our Tokio timeout always fires first.
///   This prevents race conditions where Windows might timeout a probe just as
///   we're processing it, leading to inconsistent behavior.
/// 
/// - **Shutdown Optimization**: When the socket is dropped with pending operations,
///   we skip calling IcmpCloseHandle to avoid a 600ms+ blocking delay. Windows
///   will clean up the handle when the process exits.
/// 
/// ## Response Validation
/// 
/// - ICMP Time Exceeded responses from intermediate routers don't echo back
///   the data payload, so we can't validate sequence numbers for those
/// - We include process ID and sequence number in echo requests to match
///   responses from the destination
pub struct WindowsAsyncIcmpSocket {
    icmp_handle: HANDLE,
    destination_reached: Arc<Mutex<bool>>,
    pending_count: Arc<Mutex<usize>>,
    timing_config: TimingConfig,
}

impl WindowsAsyncIcmpSocket {
    /// Create a new Windows async ICMP socket
    pub fn new_with_config(timing_config: TimingConfig) -> Result<Self> {
        let icmp_handle = unsafe { IcmpCreateFile() };
        if icmp_handle == ptr::null_mut() {
            return Err(anyhow!("Failed to create ICMP handle"));
        }

        Ok(Self {
            icmp_handle,
            destination_reached: Arc::new(Mutex::new(false)),
            pending_count: Arc::new(Mutex::new(0)),
            timing_config,
        })
    }

    /// Process ICMP response
    fn process_response(
        &self,
        buffer: &[u8],
        sequence: u16,
        ttl: u8,
        sent_at: Instant,
    ) -> Result<ProbeResponse> {
        if buffer.len() < mem::size_of::<ICMP_ECHO_REPLY>() {
            return Err(anyhow!("Response buffer too small"));
        }

        let reply = unsafe { &*(buffer.as_ptr() as *const ICMP_ECHO_REPLY) };
        let elapsed = sent_at.elapsed();
        
        // Verify the response data matches our probe
        // Only Echo Reply (destination reached) includes our data
        // Time Exceeded and other ICMP errors don't echo the data back
        if reply.Status == IP_SUCCESS {
            // This is an Echo Reply - verify it's our probe
            if buffer.len() >= mem::size_of::<ICMP_ECHO_REPLY>() + 4 {
                let data_offset = mem::size_of::<ICMP_ECHO_REPLY>();
                let data = &buffer[data_offset..];
                
                if data.len() >= 4 {
                    let identifier = u16::from_be_bytes([data[0], data[1]]);
                    let recv_sequence = u16::from_be_bytes([data[2], data[3]]);
                    
                    // Verify this response is for our process and sequence
                    let expected_identifier = std::process::id() as u16;
                    if identifier != expected_identifier || recv_sequence != sequence {
                        return Err(anyhow!(
                            "Response mismatch: expected id={}/seq={}, got id={}/seq={}",
                            expected_identifier, sequence, identifier, recv_sequence
                        ));
                    }
                }
            }
        }

        // Check for timeout or failure statuses
        match reply.Status {
            IP_REQ_TIMED_OUT | IP_GENERAL_FAILURE => {
                // This probe timed out - return a timeout response
                return Ok(ProbeResponse {
                    from_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED), // 0.0.0.0
                    sequence,
                    ttl,
                    rtt: elapsed,
                    received_at: Instant::now(),
                    is_destination: false,
                    is_timeout: true,
                });
            }
            _ => {}
        }

        // Extract the responding IP address
        let from_addr = IpAddr::V4(Ipv4Addr::new(
            (reply.Address >> 0) as u8,
            (reply.Address >> 8) as u8,
            (reply.Address >> 16) as u8,
            (reply.Address >> 24) as u8,
        ));

        // Check if we reached the destination
        let is_destination = reply.Status == IP_SUCCESS;
        if is_destination {
            *self.destination_reached.lock().unwrap() = true;
        }

        // Use the Windows API's RoundTripTime (in milliseconds)
        let rtt = if reply.RoundTripTime > 0 {
            Duration::from_millis(reply.RoundTripTime as u64)
        } else {
            // For sub-millisecond responses, use our elapsed time
            elapsed
        };

        Ok(ProbeResponse {
            from_addr,
            sequence,
            ttl,
            rtt,
            received_at: Instant::now(),
            is_destination,
            is_timeout: false,
        })
    }
}

#[async_trait]
impl AsyncProbeSocket for WindowsAsyncIcmpSocket {
    fn mode(&self) -> ProbeMode {
        ProbeMode::WindowsIcmp
    }

    async fn send_probe_and_recv(&self, dest: IpAddr, probe: ProbeInfo) -> Result<ProbeResponse> {
        let dest_addr = match dest {
            IpAddr::V4(addr) => addr,
            _ => return Err(anyhow!("Only IPv4 is supported")),
        };

        // Increment pending count
        {
            let mut count = self.pending_count.lock().unwrap();
            *count += 1;
        }

        // Create event for this probe
        let event = unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) };
        if event == ptr::null_mut() {
            let mut count = self.pending_count.lock().unwrap();
            *count -= 1;
            return Err(anyhow!("Failed to create event"));
        }

        // Prepare send buffer with identifier and sequence number
        let identifier = std::process::id() as u16;
        let mut send_data = Vec::with_capacity(32);
        send_data.extend_from_slice(&identifier.to_be_bytes());
        send_data.extend_from_slice(&probe.sequence.to_be_bytes());
        // Pad to 32 bytes total
        send_data.extend_from_slice(b"ftr-windows-padding");
        send_data.resize(32, 0);

        // Prepare reply buffer - Box it to ensure stable memory location
        let reply_size = mem::size_of::<ICMP_ECHO_REPLY>() + send_data.len() + 8;
        let reply_buffer = Box::pin(vec![0u8; reply_size]);
        let reply_ptr = reply_buffer.as_ptr() as *mut c_void;

        let sent_at = Instant::now();

        // Send ICMP request in its own scope to ensure options is dropped before await
        let send_result = {
            // Create IP options
            let mut options = IP_OPTION_INFORMATION {
                Ttl: probe.ttl,
                Tos: 0,
                Flags: 0,
                OptionsSize: 0,
                OptionsData: ptr::null_mut(),
            };

            // Send ICMP request
            let result = unsafe {
                IcmpSendEcho2(
                    self.icmp_handle,
                    event,
                    None,        // No APC routine
                    ptr::null(), // No APC context
                    u32::from_ne_bytes(dest_addr.octets()),
                    send_data.as_ptr() as *const c_void,
                    send_data.len() as u16,
                    &mut options as *mut IP_OPTION_INFORMATION,
                    reply_ptr,
                    reply_size as u32,
                    // Calculate Windows timeout with buffer to ensure our Tokio timeout fires first
                    // This prevents race conditions between Windows and Tokio timeouts
                    {
                        let user_timeout_ms = self.timing_config.socket_read_timeout.as_millis() as u32;
                        let windows_timeout = user_timeout_ms + crate::config::timing::WINDOWS_ICMP_TIMEOUT_BUFFER_MS;
                        // Ensure minimum timeout for Windows ICMP API stability
                        windows_timeout.max(crate::config::timing::WINDOWS_ICMP_MIN_TOTAL_TIMEOUT_MS)
                    },
                )
            };

            if result == 0 {
                let error = unsafe { GetLastError() };
                if error != ERROR_IO_PENDING {
                    Err(error)
                } else {
                    Ok(())
                }
            } else {
                Ok(())
            }
        };

        if let Err(error) = send_result {
            unsafe { CloseHandle(event) };
            let mut count = self.pending_count.lock().unwrap();
            *count -= 1;
            return Err(anyhow!("IcmpSendEcho2 failed: {}", error));
        }

        // Create oneshot channel for async coordination
        let (tx, rx) = oneshot::channel();
        let event_handle = event as usize; // Convert to usize for Send safety
        let pending_count = Arc::clone(&self.pending_count);

        // Spawn blocking task to wait for Windows event
        // Move the reply_buffer into the task to keep it alive
        let wait_handle = tokio::task::spawn_blocking(move || {
            let event = event_handle as HANDLE; // Convert back to HANDLE
            let result = unsafe { 
                WaitForSingleObject(event, 0xFFFFFFFF) // INFINITE - wait indefinitely, tokio timeout handles the actual timeout
            };
            unsafe { CloseHandle(event) };

            // Decrement pending count
            let mut count = pending_count.lock().unwrap();
            *count = count.saturating_sub(1);

            if result == WAIT_OBJECT_0 {
                // Send the buffer back through the channel
                tx.send(Ok(reply_buffer)).ok();
            } else {
                tx.send(Err(anyhow!("Event wait failed or timed out"))).ok();
            }
        });

        // Wait for the event to be signaled with our actual timeout
        let timeout_duration = self.timing_config.socket_read_timeout;
        
        // Debug logging for timeout analysis
        let verbose = std::env::var("FTR_VERBOSE")
            .ok()
            .and_then(|v| v.parse::<u8>().ok())
            .unwrap_or(0);
        
        if verbose >= 3 {
            let windows_timeout_ms = {
                let user_timeout_ms = self.timing_config.socket_read_timeout.as_millis() as u32;
                let windows_timeout = user_timeout_ms + crate::config::timing::WINDOWS_ICMP_TIMEOUT_BUFFER_MS;
                windows_timeout.max(crate::config::timing::WINDOWS_ICMP_MIN_TOTAL_TIMEOUT_MS)
            };
            eprintln!("[TIMEOUT] Probe seq={} ttl={}: User timeout={}ms, Windows timeout={}ms", 
                probe.sequence, probe.ttl, timeout_duration.as_millis(), windows_timeout_ms);
        }
        
        match tokio::time::timeout(timeout_duration, rx).await {
            Ok(Ok(Ok(reply_buffer))) => {
                // Got a response - process it
                self.process_response(&reply_buffer, probe.sequence, probe.ttl, sent_at)
            }
            Ok(Ok(Err(e))) => {
                // Event wait error
                Err(anyhow!("Event wait error: {}", e))
            }
            Ok(Err(_)) => {
                // Channel was dropped (shouldn't happen)
                Err(anyhow!("Event wait cancelled"))
            }
            Err(_) => {
                // Tokio timeout elapsed before Windows completed
                // Since we gave Windows a longer timeout (user timeout + buffer),
                // this ensures consistent behavior where our timeout always wins
                // 
                // We let the Windows operation complete in the background rather
                // than trying to cancel it, which would cause issues
                drop(wait_handle); // Let the task complete in background
                
                Ok(ProbeResponse {
                    from_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                    sequence: probe.sequence,
                    ttl: probe.ttl,
                    rtt: timeout_duration,
                    received_at: Instant::now(),
                    is_destination: false,
                    is_timeout: true,
                })
            }
        }
    }

    fn destination_reached(&self) -> bool {
        *self.destination_reached.lock().unwrap()
    }

    fn pending_count(&self) -> usize {
        *self.pending_count.lock().unwrap()
    }
}

impl Drop for WindowsAsyncIcmpSocket {
    fn drop(&mut self) {
        if self.icmp_handle != ptr::null_mut() {
            let pending = *self.pending_count.lock().unwrap();
            if pending > 0 {
                // Performance optimization: Skip IcmpCloseHandle when there are pending operations
                // 
                // IcmpCloseHandle blocks until all pending operations complete, which can take
                // 600ms+ if operations are waiting for timeout. Since we're shutting down anyway,
                // we let Windows clean up the handle on process exit.
                // 
                // This optimization reduces shutdown time from ~700ms to <100ms when probes
                // are in flight.
            } else {
                // No pending operations, safe to close immediately
                unsafe { IcmpCloseHandle(self.icmp_handle) };
            }
        }
    }
}

// Safety: The socket handle is properly synchronized
unsafe impl Send for WindowsAsyncIcmpSocket {}
unsafe impl Sync for WindowsAsyncIcmpSocket {}
