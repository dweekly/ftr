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

        // Prepare send buffer
        let send_data = vec![0u8; 32];

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
                    self.timing_config.socket_read_timeout.as_millis() as u32,
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
        tokio::task::spawn_blocking(move || {
            let event = event_handle as HANDLE; // Convert back to HANDLE
            let result = unsafe { WaitForSingleObject(event, 0xFFFFFFFF) }; // INFINITE
            unsafe { CloseHandle(event) };

            // Decrement pending count
            let mut count = pending_count.lock().unwrap();
            *count = count.saturating_sub(1);

            if result == WAIT_OBJECT_0 {
                // Send the buffer back through the channel
                tx.send(Ok(reply_buffer)).ok();
            } else {
                tx.send(Err(anyhow!("Event wait failed"))).ok();
            }
        });

        // Wait for the event to be signaled and get the buffer back
        let reply_buffer = rx
            .await
            .map_err(|_| anyhow!("Event wait cancelled"))?
            .map_err(|e| anyhow!("Event wait error: {}", e))?;

        // Process the response
        self.process_response(&reply_buffer, probe.sequence, probe.ttl, sent_at)
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
            unsafe { IcmpCloseHandle(self.icmp_handle) };
        }
    }
}

// Safety: The socket handle is properly synchronized
unsafe impl Send for WindowsAsyncIcmpSocket {}
unsafe impl Sync for WindowsAsyncIcmpSocket {}
