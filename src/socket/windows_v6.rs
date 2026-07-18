//! Windows async ICMPv6 socket using Tokio
//!
//! IPv6 counterpart of [`super::windows`]: echo requests go through the
//! IP Helper `Icmp6CreateFile`/`Icmp6SendEcho2`/`Icmp6ParseReplies` API
//! with Tokio's async primitives for immediate response notification. No
//! elevation is required — the API works from a normal user context, same
//! as v4.
//!
//! All behavior below was validated live in a Windows 11 (ARM64) VM by
//! `examples/spike_windows_v6.rs` (findings recorded in
//! `docs/IPV6_DESIGN.md`):
//!
//! - Passing the unspecified address `::` (with `sin6_family = AF_INET6`)
//!   as the required source sockaddr lets the stack perform normal source
//!   address selection — no interface enumeration needed.
//! - The `IP_OPTION_INFORMATION.Ttl` field sets the outgoing hop limit,
//!   exactly like v4, and intermediate routers surface as replies with
//!   `Status = IP_HOP_LIMIT_EXCEEDED` (11013).
//! - The reply buffer holds an `ICMPV6_ECHO_REPLY_LH` (36 bytes: packed
//!   26-byte `IPV6_ADDRESS_EX`, 2 bytes padding, `Status` at offset 28,
//!   `RoundTripTime` at offset 32) followed by the echoed request payload
//!   for Echo Replies. Time Exceeded replies do not echo the payload —
//!   same asymmetry as v4.
//! - `IPV6_ADDRESS_EX.sin6_addr` is `[u16; 8]` whose words carry the
//!   address bytes in network order.
//! - On timeout the event still signals; `Icmp6ParseReplies` returns 0
//!   and the status field reads `IP_REQ_TIMED_OUT` (11010).

use crate::TimingConfig;
use crate::probe::{ProbeInfo, ProbeResponse};
use crate::socket::traits::{ProbeMode, ProbeSocket};
use crate::traceroute::TracerouteError;
use std::ffi::c_void;
use std::future::Future;
use std::mem;
use std::net::{IpAddr, Ipv6Addr};
use std::pin::Pin;
use std::ptr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::oneshot;
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_IO_PENDING, GetLastError, HANDLE, WAIT_OBJECT_0,
};
// Unlike super::windows (which predates windows-sys exporting them), the
// status codes come straight from windows-sys: IP_REQ_TIMED_OUT = 11010,
// IP_GENERAL_FAILURE = 11050, IP_SUCCESS = 0 (ipexport.h values).
use windows_sys::Win32::NetworkManagement::IpHelper::{
    ICMPV6_ECHO_REPLY_LH, IP_GENERAL_FAILURE, IP_OPTION_INFORMATION, IP_REQ_TIMED_OUT, IP_SUCCESS,
    Icmp6CreateFile, Icmp6ParseReplies, Icmp6SendEcho2, IcmpCloseHandle,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET6, SOCKADDR_IN6};
use windows_sys::Win32::System::Threading::{CreateEventW, WaitForSingleObject};

/// Windows async ICMPv6 socket implementation
///
/// Uses the Windows `Icmp6SendEcho2` API for sending ICMPv6 echo requests.
/// The async design — event handle per probe, `spawn_blocking` waiter,
/// Tokio timeout with a Windows-side buffer — mirrors
/// [`super::windows::WindowsAsyncIcmpSocket`]; see that type and
/// `docs/WINDOWS_ASYNC_FINDINGS.md` for why this shape won.
pub struct WindowsAsyncIcmpV6Socket {
    icmp_handle: HANDLE,
    destination_reached: Arc<Mutex<bool>>,
    pending_count: Arc<Mutex<usize>>,
    timing_config: TimingConfig,
    verbose: u8,
}

/// Build a `SOCKADDR_IN6` for `Icmp6SendEcho2` from an address.
///
/// `scope_id` stays 0: `Ipv6Addr` carries no zone, and the spike's global
/// unicast targets needed none. Link-local targets would need the caller
/// to plumb a zone through — not supported yet on any ftr platform.
fn sockaddr_in6(addr: Ipv6Addr) -> SOCKADDR_IN6 {
    let mut sa: SOCKADDR_IN6 = unsafe { mem::zeroed() };
    sa.sin6_family = AF_INET6;
    sa.sin6_addr.u.Byte = addr.octets();
    sa
}

/// Reconstruct the reply source address from `IPV6_ADDRESS_EX.sin6_addr`.
///
/// The field is `[u16; 8]` holding the 16 address bytes in network order
/// (spike-verified against known router addresses), so re-serializing each
/// word with native endianness recovers the wire bytes on any host.
fn ipv6_from_reply_words(words: [u16; 8]) -> Ipv6Addr {
    let mut octets = [0u8; 16];
    for (i, w) in words.iter().enumerate() {
        octets[i * 2..i * 2 + 2].copy_from_slice(&w.to_ne_bytes());
    }
    Ipv6Addr::from(octets)
}

/// Parse one reply buffer into a `ProbeResponse` (no socket state — the
/// caller updates `destination_reached`). `elapsed` is the locally
/// measured round-trip, used when the API reports a sub-millisecond 0.
fn parse_reply(
    buffer: &[u8],
    sequence: u16,
    ttl: u8,
    elapsed: Duration,
) -> Result<ProbeResponse, TracerouteError> {
    if buffer.len() < mem::size_of::<ICMPV6_ECHO_REPLY_LH>() {
        return Err(TracerouteError::SocketError(
            "ICMPv6 response buffer too small".to_string(),
        ));
    }

    // SAFETY: length checked above; read_unaligned tolerates the Vec<u8>
    // buffer's 1-byte alignment (the struct wants 4).
    let reply = unsafe { ptr::read_unaligned(buffer.as_ptr() as *const ICMPV6_ECHO_REPLY_LH) };

    // Echo Replies (destination reached) echo our request payload right
    // after the reply struct (spike-verified offset); Time Exceeded and
    // other ICMPv6 errors don't echo it back — same asymmetry as v4.
    if reply.Status == IP_SUCCESS {
        let data_offset = mem::size_of::<ICMPV6_ECHO_REPLY_LH>();
        let data = &buffer[data_offset..];
        if data.len() >= 4 {
            let identifier = u16::from_be_bytes([data[0], data[1]]);
            let recv_sequence = u16::from_be_bytes([data[2], data[3]]);

            let expected_identifier = std::process::id() as u16;
            if identifier != expected_identifier || recv_sequence != sequence {
                return Err(TracerouteError::SocketError(format!(
                    "ICMPv6 response mismatch: expected id={}/seq={}, got id={}/seq={}",
                    expected_identifier, sequence, identifier, recv_sequence
                )));
            }
        }
    }

    if reply.Status == IP_REQ_TIMED_OUT || reply.Status == IP_GENERAL_FAILURE {
        return Ok(ProbeResponse {
            from_addr: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            sequence,
            ttl,
            rtt: elapsed,
            received_at: Instant::now(),
            is_destination: false,
            is_timeout: true,
        });
    }

    let from_addr = IpAddr::V6(ipv6_from_reply_words(reply.Address.sin6_addr));
    let is_destination = reply.Status == IP_SUCCESS;

    // Use the Windows API's RoundTripTime (milliseconds); it reads 0 for
    // sub-millisecond responses, where our own elapsed time is better.
    let rtt = if reply.RoundTripTime > 0 {
        Duration::from_millis(reply.RoundTripTime as u64)
    } else {
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

impl WindowsAsyncIcmpV6Socket {
    /// Create a new Windows async ICMPv6 socket with an explicit
    /// verbosity level
    pub fn new_with_config_and_verbose(
        timing_config: TimingConfig,
        verbose: u8,
    ) -> Result<Self, TracerouteError> {
        let icmp_handle = unsafe { Icmp6CreateFile() };
        if icmp_handle.is_null() {
            return Err(TracerouteError::SocketError(
                "Failed to create ICMPv6 handle".to_string(),
            ));
        }

        Ok(Self {
            icmp_handle,
            destination_reached: Arc::new(Mutex::new(false)),
            pending_count: Arc::new(Mutex::new(0)),
            timing_config,
            verbose,
        })
    }

    /// Windows-side timeout: user timeout plus a buffer so the Tokio
    /// timeout always fires first (same race-avoidance as v4 — see
    /// `docs/WINDOWS_ASYNC_FINDINGS.md`), floored at the empirical
    /// minimum below which the Windows ICMP API misbehaves.
    fn windows_timeout_ms(&self) -> u32 {
        let user_timeout_ms = self.timing_config.socket_read_timeout.as_millis() as u32;
        let windows_timeout =
            user_timeout_ms + crate::config::timing::WINDOWS_ICMP_TIMEOUT_BUFFER_MS;
        windows_timeout.max(crate::config::timing::WINDOWS_ICMP_MIN_TOTAL_TIMEOUT_MS)
    }
}

impl ProbeSocket for WindowsAsyncIcmpV6Socket {
    fn mode(&self) -> ProbeMode {
        ProbeMode::WindowsIcmp
    }

    fn send_probe_and_recv(
        &self,
        dest: IpAddr,
        probe: ProbeInfo,
    ) -> Pin<Box<dyn Future<Output = Result<ProbeResponse, TracerouteError>> + Send + '_>> {
        Box::pin(async move {
            let dest_addr = match dest {
                IpAddr::V6(addr) => addr,
                IpAddr::V4(_) => {
                    return Err(TracerouteError::SocketError(
                        "ICMPv6 socket cannot probe an IPv4 destination".to_string(),
                    ));
                }
            };

            {
                let mut count = self
                    .pending_count
                    .lock()
                    .expect("Failed to acquire pending_count lock");
                *count += 1;
            }

            // Create event for this probe
            let event = unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) };
            if event.is_null() {
                let mut count = self
                    .pending_count
                    .lock()
                    .expect("Failed to acquire pending_count lock");
                *count -= 1;
                return Err(TracerouteError::SocketError(
                    "Failed to create event".to_string(),
                ));
            }

            // Identifier + sequence payload, same shape as v4 (Echo
            // Replies echo it back; used to reject foreign replies).
            let identifier = std::process::id() as u16;
            let mut send_data = Vec::with_capacity(32);
            send_data.extend_from_slice(&identifier.to_be_bytes());
            send_data.extend_from_slice(&probe.sequence.to_be_bytes());
            send_data.extend_from_slice(b"ftr-windows-padding");
            send_data.resize(32, 0);

            // Reply buffer sized per the Icmp6SendEcho2 contract: one
            // ICMPV6_ECHO_REPLY plus the echoed data plus 8 bytes for an
            // ICMP error message. Boxed for a stable location across the
            // await.
            let reply_size = mem::size_of::<ICMPV6_ECHO_REPLY_LH>() + send_data.len() + 8;
            let mut reply_buffer = Box::pin(vec![0u8; reply_size]);
            let reply_ptr = reply_buffer.as_mut_ptr() as *mut c_void;

            let sent_at = Instant::now();

            // Source `::` = let the stack pick (spike-validated);
            // destination carries the target.
            let source = sockaddr_in6(Ipv6Addr::UNSPECIFIED);
            let dest_sa = sockaddr_in6(dest_addr);

            // Send in its own scope so options is dropped before the await
            let send_result = {
                let options = IP_OPTION_INFORMATION {
                    Ttl: probe.ttl,
                    Tos: 0,
                    Flags: 0,
                    OptionsSize: 0,
                    OptionsData: ptr::null_mut(),
                };

                let result = unsafe {
                    Icmp6SendEcho2(
                        self.icmp_handle,
                        event,
                        None,        // No APC routine
                        ptr::null(), // No APC context
                        &source,
                        &dest_sa,
                        send_data.as_ptr() as *const c_void,
                        send_data.len() as u16,
                        &options as *const IP_OPTION_INFORMATION,
                        reply_ptr,
                        reply_size as u32,
                        self.windows_timeout_ms(),
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
                let mut count = self
                    .pending_count
                    .lock()
                    .expect("Failed to acquire pending_count lock");
                *count -= 1;
                return Err(TracerouteError::SocketError(format!(
                    "Icmp6SendEcho2 failed: {}",
                    error
                )));
            }

            // Oneshot channel + spawn_blocking waiter, as in v4. The
            // reply buffer moves into the task so it stays alive even if
            // our Tokio timeout abandons the wait.
            let (tx, rx) = oneshot::channel();
            let event_handle = event as usize; // usize for Send safety
            let pending_count = Arc::clone(&self.pending_count);

            let wait_handle = tokio::task::spawn_blocking(move || {
                let event = event_handle as HANDLE;
                let result = unsafe {
                    // INFINITE: the Tokio timeout owns cancellation; the
                    // Windows-side timeout (set above) signals the event.
                    WaitForSingleObject(event, 0xFFFFFFFF)
                };
                unsafe { CloseHandle(event) };

                let mut count = pending_count
                    .lock()
                    .expect("Failed to acquire pending_count lock");
                *count = count.saturating_sub(1);

                if result == WAIT_OBJECT_0 {
                    // Async completions must go through Icmp6ParseReplies
                    // (per the API contract; spike-confirmed it fixes up
                    // the buffer and reports the reply count — 0 means
                    // timeout/error, with the status also readable in the
                    // buffer's Status field).
                    let mut buffer = reply_buffer;
                    let parsed = unsafe {
                        Icmp6ParseReplies(buffer.as_mut_ptr() as *mut c_void, reply_size as u32)
                    };
                    tx.send(Ok((buffer, parsed))).ok();
                } else {
                    tx.send(Err(TracerouteError::SocketError(
                        "Event wait failed or timed out".to_string(),
                    )))
                    .ok();
                }
            });

            let timeout_duration = self.timing_config.socket_read_timeout;

            if self.verbose >= 3 {
                eprintln!(
                    "[TIMEOUT] ICMPv6 probe seq={} ttl={}: User timeout={}ms, Windows timeout={}ms",
                    probe.sequence,
                    probe.ttl,
                    timeout_duration.as_millis(),
                    self.windows_timeout_ms()
                );
            }

            match tokio::time::timeout(timeout_duration, rx).await {
                Ok(Ok(Ok((reply_buffer, parsed)))) => {
                    if parsed == 0 {
                        // Windows-side timeout or send error surfaced via
                        // parse (status IP_REQ_TIMED_OUT in the buffer)
                        return Ok(ProbeResponse {
                            from_addr: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                            sequence: probe.sequence,
                            ttl: probe.ttl,
                            rtt: sent_at.elapsed(),
                            received_at: Instant::now(),
                            is_destination: false,
                            is_timeout: true,
                        });
                    }
                    let response =
                        parse_reply(&reply_buffer, probe.sequence, probe.ttl, sent_at.elapsed())?;
                    if response.is_destination {
                        *self
                            .destination_reached
                            .lock()
                            .expect("Failed to acquire destination_reached lock") = true;
                    }
                    Ok(response)
                }
                Ok(Ok(Err(e))) => Err(TracerouteError::SocketError(format!(
                    "Event wait error: {}",
                    e
                ))),
                Ok(Err(_)) => Err(TracerouteError::SocketError(
                    "Event wait cancelled".to_string(),
                )),
                Err(_) => {
                    // Tokio timeout fired first (guaranteed by the
                    // Windows-side buffer); let the blocking task finish
                    // in the background rather than cancelling it.
                    drop(wait_handle);

                    Ok(ProbeResponse {
                        from_addr: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                        sequence: probe.sequence,
                        ttl: probe.ttl,
                        rtt: timeout_duration,
                        received_at: Instant::now(),
                        is_destination: false,
                        is_timeout: true,
                    })
                }
            }
        })
    }

    fn destination_reached(&self) -> bool {
        *self
            .destination_reached
            .lock()
            .expect("Failed to acquire destination_reached lock")
    }

    fn pending_count(&self) -> usize {
        *self
            .pending_count
            .lock()
            .expect("Failed to acquire pending_count lock")
    }
}

impl Drop for WindowsAsyncIcmpV6Socket {
    fn drop(&mut self) {
        if !self.icmp_handle.is_null() {
            let pending = *self
                .pending_count
                .lock()
                .expect("Failed to acquire pending_count lock");
            if pending == 0 {
                // With pending operations we skip IcmpCloseHandle — it
                // blocks until they complete (600ms+); Windows reclaims
                // the handle at process exit. Same optimization as v4.
                unsafe { IcmpCloseHandle(self.icmp_handle) };
            }
        }
    }
}

// Safety: the ICMP handle is only used for Icmp6SendEcho2 calls, which the
// IP Helper API allows from any thread; shared state is behind mutexes.
unsafe impl Send for WindowsAsyncIcmpV6Socket {}
unsafe impl Sync for WindowsAsyncIcmpV6Socket {}

#[cfg(test)]
mod tests {
    use super::*;

    use windows_sys::Win32::NetworkManagement::IpHelper::IP_HOP_LIMIT_EXCEEDED;

    /// Build a synthetic reply buffer with the spike-verified layout:
    /// packed IPV6_ADDRESS_EX at 0 (address words at byte 6, network
    /// order), Status at 28, RoundTripTime at 32, echoed data at 36.
    fn synthetic_reply(addr: Ipv6Addr, status: u32, rtt_ms: u32, echoed: &[u8]) -> Vec<u8> {
        let mut buf = vec![0u8; mem::size_of::<ICMPV6_ECHO_REPLY_LH>() + echoed.len()];
        buf[6..22].copy_from_slice(&addr.octets());
        buf[28..32].copy_from_slice(&status.to_ne_bytes());
        buf[32..36].copy_from_slice(&rtt_ms.to_ne_bytes());
        buf[36..].copy_from_slice(echoed);
        buf
    }

    /// The echoed payload our own probes carry (checked on Echo Replies).
    fn own_payload(sequence: u16) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&(std::process::id() as u16).to_be_bytes());
        data.extend_from_slice(&sequence.to_be_bytes());
        data.extend_from_slice(b"ftr-windows-padding");
        data.resize(32, 0);
        data
    }

    #[test]
    fn test_struct_layout_matches_spike_observations() {
        // Guard against windows-sys layout drift: the spike measured
        // these sizes live (ICMPV6_ECHO_REPLY_LH=36, IPV6_ADDRESS_EX=26).
        assert_eq!(mem::size_of::<ICMPV6_ECHO_REPLY_LH>(), 36);
        assert_eq!(
            mem::size_of::<windows_sys::Win32::NetworkManagement::IpHelper::IPV6_ADDRESS_EX>(),
            26
        );
    }

    #[test]
    fn test_parse_hop_limit_exceeded_reply() {
        let router: Ipv6Addr = "2001:db8:1::1".parse().expect("addr parses");
        // Time Exceeded does not echo the payload (spike-observed zeros)
        let buf = synthetic_reply(router, IP_HOP_LIMIT_EXCEEDED, 7, &[0u8; 32]);

        let resp = parse_reply(&buf, 42, 3, Duration::from_millis(9)).expect("parses");
        assert_eq!(resp.from_addr, IpAddr::V6(router));
        assert_eq!(resp.sequence, 42);
        assert_eq!(resp.ttl, 3);
        assert!(!resp.is_destination);
        assert!(!resp.is_timeout);
        assert_eq!(resp.rtt, Duration::from_millis(7));
    }

    #[test]
    fn test_parse_destination_echo_reply() {
        let dest: Ipv6Addr = "2001:4860:4860::8888".parse().expect("addr parses");
        let buf = synthetic_reply(dest, IP_SUCCESS, 3, &own_payload(7));

        let resp = parse_reply(&buf, 7, 30, Duration::from_millis(4)).expect("parses");
        assert_eq!(resp.from_addr, IpAddr::V6(dest));
        assert!(resp.is_destination);
        assert!(!resp.is_timeout);
        assert_eq!(resp.rtt, Duration::from_millis(3));
    }

    #[test]
    fn test_parse_uses_elapsed_for_zero_rtt() {
        let dest: Ipv6Addr = "::1".parse().expect("addr parses");
        let buf = synthetic_reply(dest, IP_SUCCESS, 0, &own_payload(1));

        let resp = parse_reply(&buf, 1, 1, Duration::from_micros(250)).expect("parses");
        assert_eq!(resp.rtt, Duration::from_micros(250));
    }

    #[test]
    fn test_parse_rejects_foreign_echo_reply() {
        let dest: Ipv6Addr = "::1".parse().expect("addr parses");
        // Same sequence but an identifier from some other process
        let mut payload = own_payload(5);
        let foreign_id = (std::process::id() as u16).wrapping_add(1);
        payload[0..2].copy_from_slice(&foreign_id.to_be_bytes());
        let buf = synthetic_reply(dest, IP_SUCCESS, 1, &payload);

        let err = parse_reply(&buf, 5, 1, Duration::from_millis(1))
            .expect_err("foreign identifier must be rejected");
        assert!(matches!(err, TracerouteError::SocketError(_)));
    }

    #[test]
    fn test_parse_timeout_status_reply() {
        let buf = synthetic_reply(Ipv6Addr::UNSPECIFIED, IP_REQ_TIMED_OUT, 0, &[0u8; 32]);

        let resp = parse_reply(&buf, 9, 5, Duration::from_millis(100)).expect("parses");
        assert!(resp.is_timeout);
        assert!(!resp.is_destination);
        assert_eq!(resp.from_addr, IpAddr::V6(Ipv6Addr::UNSPECIFIED));
    }

    #[test]
    fn test_parse_rejects_short_buffer() {
        let buf = vec![0u8; mem::size_of::<ICMPV6_ECHO_REPLY_LH>() - 1];
        assert!(parse_reply(&buf, 0, 1, Duration::ZERO).is_err());
    }

    #[test]
    fn test_reply_words_network_byte_order() {
        // The spike observed 2001:4860:4860::8888 arriving as bytes
        // 20 01 48 60 48 60 00 .. 88 88 at the word field; reading those
        // bytes as native u16s and re-serializing must round-trip.
        let expected: Ipv6Addr = "2001:4860:4860::8888".parse().expect("addr parses");
        let wire: [u8; 16] = expected.octets();
        let mut words = [0u16; 8];
        for (i, w) in words.iter_mut().enumerate() {
            *w = u16::from_ne_bytes([wire[i * 2], wire[i * 2 + 1]]);
        }
        assert_eq!(ipv6_from_reply_words(words), expected);
    }
}
