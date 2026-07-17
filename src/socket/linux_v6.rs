//! Linux async IPv6 socket implementations for traceroute
//!
//! Three probe modes, mirroring the IPv4 design in [`super::linux`] and the
//! kernel behavior validated live on Ubuntu 24.04 / kernel 6.8 by
//! `examples/spike_linux_v6.rs` (findings recorded in `docs/IPV6_DESIGN.md`):
//!
//! 1. **[`LinuxAsyncUdpV6Socket`]** (primary, unprivileged): UDP probes with
//!    `IPV6_UNICAST_HOPS` per hop and `IPV6_RECVERR`; ICMPv6 errors are read
//!    from the socket error queue via `recvmsg(MSG_ERRQUEUE)` exactly like
//!    the v4 `IP_RECVERR` mode. Works with default sysctls, no root —
//!    spike-validated with a complete 15-hop live traceroute.
//! 2. **[`LinuxAsyncPingV6Socket`]** (unprivileged where
//!    `net.ipv4.ping_group_range` covers the gid — note the *ipv4-named*
//!    sysctl gates ICMPv6 ping sockets too; the kernel default `1 0`
//!    disables them): ICMPv6 echo probes on `SOCK_DGRAM`/`IPPROTO_ICMPV6`
//!    ping sockets. The kernel REWRITES the echo identifier to a per-socket
//!    value (readable via `getsockname`) and demuxes replies per-socket, so
//!    matching is by sequence number only. Echo replies arrive on the
//!    normal receive path; Time Exceeded arrives ONLY via the errqueue
//!    (with `IPV6_RECVERR` off it is dropped entirely) — all spike-validated.
//! 3. **[`LinuxAsyncRawIcmpV6Socket`]** (root / `CAP_NET_RAW`): raw ICMPv6
//!    echo probes. Time Exceeded arrives on the normal receive path (no
//!    errqueue needed), the kernel computes ICMPv6 checksums even on raw
//!    sends, and received buffers start at the ICMPv6 header — all
//!    spike-validated (container run, same kernel).
//!
//! `ICMP6_FILTER` on Linux is optname 1 with semantics INVERTED vs
//! BSD/Darwin (bit SET = BLOCK) and is only usable on raw sockets — ping
//! sockets reject it with ENOPROTOOPT (spike-validated positive control).

use super::traits::{ProbeMode, ProbeSocket};
use crate::probe::{ProbeInfo, ProbeResponse};
use crate::socket::icmpv6;
use crate::traceroute::TracerouteError;
use socket2::{Domain, Protocol, SockAddr, Socket as Socket2, Type};
use std::future::Future;
use std::net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::os::unix::io::AsRawFd;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::oneshot;

/// `IPV6_RECVERR` socket option at level `IPPROTO_IPV6`. Verified on Ubuntu
/// 24.04: `/usr/include/linux/in6.h` line 178 (`#define IPV6_RECVERR 25`) —
/// same citation as the validation spike.
const IPV6_RECVERR: libc::c_int = 25;

/// `sock_extended_err.ee_origin` for errors that arrived as ICMPv6:
/// `/usr/include/linux/errqueue.h` line 31 (`#define SO_EE_ORIGIN_ICMP6 3`).
const SO_EE_ORIGIN_ICMP6: u8 = 3;

/// `ICMPV6_FILTER` socket option at level `IPPROTO_ICMPV6`. Verified on
/// Ubuntu 24.04: `/usr/include/linux/icmpv6.h` line 150
/// (`#define ICMPV6_FILTER 1`) and glibc `/usr/include/netinet/icmp6.h`
/// line 26 (`#define ICMP6_FILTER 1`). Darwin uses 18 instead, with
/// inverted bit semantics — see [`Icmp6FilterLinux`].
const ICMPV6_FILTER: libc::c_int = 1;

/// ICMPv6 Destination Unreachable code 4 = port unreachable — what the
/// final destination answers to a UDP probe (RFC 4443 section 3.1). On the
/// errqueue this surfaces with `ee_errno=111` (ECONNREFUSED), while Time
/// Exceeded surfaces as `ee_errno=113` (EHOSTUNREACH); the authoritative
/// ICMPv6 type/code are `ee_type`/`ee_code` (spike-validated mapping).
const ICMPV6_UNREACH_PORT: u8 = 4;

/// Traditional traceroute UDP destination port, matching the IPv4 UDP mode
/// in [`super::linux`].
const UDP_DEST_PORT: u16 = 33434;

/// Response poll budget: 1000 retries at 1 ms intervals = 1 s, matching the
/// IPv4 implementations in [`super::linux`].
const MAX_RETRIES: u32 = 1000;

/// Interval between response polls, matching [`super::linux`].
const POLL_INTERVAL: Duration = Duration::from_millis(1);

/// Receive buffer size — a full Ethernet-MTU packet comfortably fits.
const RECV_BUFFER_SIZE: usize = 1500;

/// Mirror of Linux `struct sock_extended_err`
/// (`/usr/include/linux/errqueue.h` line 15), same shape as the IPv4 one in
/// [`super::linux`].
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

/// Byte size of [`SockExtendedErr`] (16: repr(C), no padding needed —
/// u32 + 4×u8 + 2×u32).
const SOCK_EXTENDED_ERR_SIZE: usize = std::mem::size_of::<SockExtendedErr>();

// `struct sockaddr_in6` field offsets (linux/in6.h; stable Linux ABI),
// used to parse the SO_EE_OFFENDER sockaddr that the kernel places
// immediately after `sock_extended_err` in the IPV6_RECVERR cmsg payload
// (SO_EE_OFFENDER macro, /usr/include/linux/errqueue.h line 37):
//   sin6_family   u16 (host order)  at offset 0
//   sin6_port     u16 (net order)   at offset 2
//   sin6_flowinfo u32               at offset 4
//   sin6_addr     [u8; 16]          at offset 8
//   sin6_scope_id u32               at offset 24
/// Offset of `sin6_addr` within `struct sockaddr_in6`.
const SIN6_ADDR_OFFSET: usize = 8;
/// Offset of `sin6_scope_id` within `struct sockaddr_in6`.
const SIN6_SCOPE_ID_OFFSET: usize = 24;
/// Total size of `struct sockaddr_in6`.
const SOCKADDR_IN6_SIZE: usize = std::mem::size_of::<libc::sockaddr_in6>();

/// One parsed `IPV6_RECVERR` control message: the extended error fields
/// plus the offender (the router/host that generated the ICMPv6 error).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RecvErrV6 {
    /// Errno the kernel mapped the ICMPv6 error to (e.g. 113 EHOSTUNREACH
    /// for Time Exceeded, 111 ECONNREFUSED for port unreachable).
    ee_errno: u32,
    /// Error origin; only [`SO_EE_ORIGIN_ICMP6`] messages concern us.
    ee_origin: u8,
    /// ICMPv6 type of the original error message.
    ee_type: u8,
    /// ICMPv6 code of the original error message.
    ee_code: u8,
    /// Offender address and scope id from the `SO_EE_OFFENDER` sockaddr,
    /// when present and `AF_INET6`. The scope id is preserved for
    /// link-local responders (address contract in `docs/IPV6_DESIGN.md`).
    offender: Option<(Ipv6Addr, u32)>,
}

/// Parse the payload of an `IPV6_RECVERR` control message: a
/// `sock_extended_err` optionally followed by the `SO_EE_OFFENDER`
/// `sockaddr_in6`. Pure byte-slice parsing (native endian for the struct
/// fields, which the kernel writes in host order) so it is unit-testable
/// with synthetic buffers.
fn parse_recverr_payload(payload: &[u8]) -> Option<RecvErrV6> {
    if payload.len() < SOCK_EXTENDED_ERR_SIZE {
        return None;
    }
    // sock_extended_err field offsets per its repr(C) layout above.
    let ee_errno = u32::from_ne_bytes(payload[0..4].try_into().ok()?);
    let ee_origin = payload[4];
    let ee_type = payload[5];
    let ee_code = payload[6];

    let offender_bytes = &payload[SOCK_EXTENDED_ERR_SIZE..];
    let offender = if offender_bytes.len() >= SOCKADDR_IN6_SIZE {
        let family = u16::from_ne_bytes(offender_bytes[0..2].try_into().ok()?);
        if family == libc::AF_INET6 as u16 {
            let addr = Ipv6Addr::from(
                <[u8; 16]>::try_from(&offender_bytes[SIN6_ADDR_OFFSET..SIN6_ADDR_OFFSET + 16])
                    .ok()?,
            );
            let scope_id = u32::from_ne_bytes(
                offender_bytes[SIN6_SCOPE_ID_OFFSET..SIN6_SCOPE_ID_OFFSET + 4]
                    .try_into()
                    .ok()?,
            );
            Some((addr, scope_id))
        } else {
            None
        }
    } else {
        None
    };

    Some(RecvErrV6 {
        ee_errno,
        ee_origin,
        ee_type,
        ee_code,
        offender,
    })
}

/// Whether an errqueue error signals that the probe reached the final
/// destination: ICMPv6 Destination Unreachable, code 4 (port unreachable) —
/// the destination's answer to a UDP probe aimed at the traceroute port
/// (spike-validated: `ee_type=1 ee_code=4 ee_errno=111`).
fn is_v6_destination_error(ee_type: u8, ee_code: u8) -> bool {
    ee_type == icmpv6::ICMPV6_DEST_UNREACHABLE && ee_code == ICMPV6_UNREACH_PORT
}

/// Result of polling a socket's error queue.
enum ErrqueueCheck {
    /// An ICMPv6-origin extended error was dequeued.
    Found(RecvErrV6),
    /// Error queue empty (or a non-ICMPv6 message was consumed).
    NoData,
    /// Unrecoverable recvmsg error.
    Error,
}

/// Poll one message off the socket's error queue via
/// `recvmsg(MSG_ERRQUEUE | MSG_DONTWAIT)` and parse its `IPV6_RECVERR`
/// control message. Mirrors the IPv4 `check_icmp_error` walker in
/// [`super::linux`], swapping `sockaddr_in`/`IPPROTO_IP`/`IP_RECVERR` for
/// their v6 counterparts.
fn check_errqueue_v6(fd: i32) -> ErrqueueCheck {
    let mut buf = [0u8; 512];
    let mut control_buf = [0u8; 512];
    // SAFETY: sockaddr_in6 is a plain-old-data C struct; all-zeroes is a
    // valid bit pattern.
    let mut from_addr: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };

    let mut iovec = libc::iovec {
        iov_base: buf.as_mut_ptr().cast(),
        iov_len: buf.len(),
    };

    // Initialize msghdr field-by-field — musl and glibc differ in field
    // types, so start zeroed and assign (same approach as the IPv4 path).
    // SAFETY: msghdr is a plain-old-data C struct; all-zeroes is valid.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = (&raw mut from_addr).cast();
    msg.msg_namelen = SOCKADDR_IN6_SIZE as libc::socklen_t;
    msg.msg_iov = &raw mut iovec;
    msg.msg_iovlen = 1;
    msg.msg_control = control_buf.as_mut_ptr().cast();
    msg.msg_controllen = control_buf.len() as _; // u32 vs usize across libcs
    msg.msg_flags = 0;

    // SAFETY: msg points at valid, live buffers (buf/control_buf/from_addr)
    // set up above; MSG_DONTWAIT keeps the call non-blocking.
    let ret = unsafe { libc::recvmsg(fd, &raw mut msg, libc::MSG_ERRQUEUE | libc::MSG_DONTWAIT) };

    if ret >= 0 {
        // SAFETY: msg was filled in by a successful recvmsg; CMSG_* walk
        // its control buffer per the documented contract.
        let mut cmsg: *const libc::cmsghdr = unsafe { libc::CMSG_FIRSTHDR(&msg) };

        while !cmsg.is_null() {
            // SAFETY: cmsg is non-null and points into control_buf per
            // CMSG_FIRSTHDR/CMSG_NXTHDR; read_unaligned tolerates any
            // alignment.
            let cmsg_hdr = unsafe { std::ptr::read_unaligned(cmsg) };

            if cmsg_hdr.cmsg_level == libc::IPPROTO_IPV6 && cmsg_hdr.cmsg_type == IPV6_RECVERR {
                // SAFETY: CMSG_DATA on a valid cmsg yields the start of its
                // payload, which for IPV6_RECVERR the kernel guarantees is a
                // sock_extended_err optionally followed by the offender
                // sockaddr (SO_EE_OFFENDER).
                let data_ptr = unsafe { libc::CMSG_DATA(cmsg) };
                // cmsg_len covers header + payload; subtract the header
                // span (data pointer minus cmsg start) to get payload size.
                let header_span = data_ptr as usize - cmsg as usize;
                let payload_len = (cmsg_hdr.cmsg_len as usize).saturating_sub(header_span);
                // SAFETY: data_ptr..data_ptr+payload_len lies within
                // control_buf, which outlives this borrow.
                let payload = unsafe { std::slice::from_raw_parts(data_ptr, payload_len) };
                if let Some(err) = parse_recverr_payload(payload) {
                    return ErrqueueCheck::Found(err);
                }
            }

            // SAFETY: msg/cmsg are valid per the loop invariant; returns
            // null at the end of the control buffer.
            cmsg = unsafe { libc::CMSG_NXTHDR(&msg, cmsg) };
        }
        ErrqueueCheck::NoData
    } else {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EAGAIN) {
            ErrqueueCheck::NoData
        } else {
            ErrqueueCheck::Error
        }
    }
}

/// Enable `IPV6_RECVERR` on a socket (socket2 has no wrapper for it).
fn set_recverr_v6(fd: i32) -> std::io::Result<()> {
    let enable: libc::c_int = 1;
    // SAFETY: fd is a valid open socket owned by the caller; the option
    // value is a c_int as `ip(7)`/`ipv6(7)` require.
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IPV6,
            IPV6_RECVERR,
            (&raw const enable).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if ret == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Mirror of `struct icmp6_filter` (glibc `netinet/icmp6.h`): 256 bits, one
/// per ICMPv6 type. **Linux semantics, INVERTED vs BSD/Darwin**: bit SET =
/// BLOCK (`ICMP6_FILTER_SETPASSALL` = memset 0, `SETBLOCKALL` = memset
/// 0xFF, `SETPASS` clears the bit — glibc `netinet/icmp6.h` lines 89-105 on
/// Ubuntu 24.04; empirically confirmed by the spike's two-phase positive
/// control on a raw socket). Do not reuse the Darwin filter from
/// `super::macos_v6`, whose bits mean PASS.
#[repr(C)]
struct Icmp6FilterLinux {
    icmp6_filt: [u32; 8],
}

impl Icmp6FilterLinux {
    /// `ICMP6_FILTER_SETBLOCKALL`: all bits set = block everything.
    fn block_all() -> Self {
        Icmp6FilterLinux {
            icmp6_filt: [u32::MAX; 8],
        }
    }

    /// `ICMP6_FILTER_SETPASS`: clear the BLOCK bit for one type
    /// (`filt[type >> 5] &= ~(1 << (type & 31))`).
    fn pass(mut self, ty: u8) -> Self {
        self.icmp6_filt[(ty >> 5) as usize] &= !(1u32 << (ty & 31));
        self
    }

    /// Whether a type would currently be passed (bit clear).
    #[cfg(test)]
    fn passes(&self, ty: u8) -> bool {
        self.icmp6_filt[(ty >> 5) as usize] & (1u32 << (ty & 31)) == 0
    }
}

/// Apply the traceroute `ICMP6_FILTER` (pass Destination Unreachable, Time
/// Exceeded, Echo Reply only) on a raw ICMPv6 socket. Best-effort noise
/// shedding: userspace identifier filtering is what guarantees correctness,
/// so failure is ignored. Only valid on raw sockets — ping sockets reject
/// this option with ENOPROTOOPT (spike-validated), and they don't need it:
/// the kernel already delivers only the socket's own echo replies.
fn apply_icmp6_filter_raw(fd: i32) {
    let filter = Icmp6FilterLinux::block_all()
        .pass(icmpv6::ICMPV6_DEST_UNREACHABLE)
        .pass(icmpv6::ICMPV6_TIME_EXCEEDED)
        .pass(icmpv6::ICMPV6_ECHO_REPLY);
    // SAFETY: fd is a valid open socket owned by the caller; the buffer is
    // a properly sized repr(C) mirror of struct icmp6_filter.
    let _ = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_ICMPV6,
            ICMPV6_FILTER,
            (&raw const filter).cast(),
            std::mem::size_of::<Icmp6FilterLinux>() as libc::socklen_t,
        )
    };
}

/// Extract the destination as `Ipv6Addr`, rejecting IPv4 targets.
fn require_v6(dest: IpAddr) -> Result<Ipv6Addr, TracerouteError> {
    match dest {
        IpAddr::V6(addr) => Ok(addr),
        IpAddr::V4(_) => Err(TracerouteError::SocketError(
            "IPv6 probe socket cannot probe an IPv4 destination".to_string(),
        )),
    }
}

/// Async UDP IPv6 socket using `IPV6_RECVERR` — the primary unprivileged
/// Linux v6 mode, mirroring the IPv4 [`super::linux::LinuxAsyncUdpSocket`].
pub struct LinuxAsyncUdpV6Socket {
    mode: ProbeMode,
    destination_reached: Arc<AtomicBool>,
    pending_count: Arc<AtomicUsize>,
    dest_port: u16,
}

impl LinuxAsyncUdpV6Socket {
    /// Create with timing configuration.
    pub fn new_with_config(_timing_config: crate::TimingConfig) -> Result<Self, TracerouteError> {
        // Probe socket creation and IPV6_RECVERR support up front so the
        // factory's fallback chain reacts to real failures at setup time,
        // not on the first probe.
        let probe = Socket2::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP)).map_err(|e| {
            TracerouteError::SocketError(format!("Failed to create UDP6 socket: {e}"))
        })?;
        set_recverr_v6(probe.as_raw_fd()).map_err(|e| {
            TracerouteError::SocketError(format!("Failed to set IPV6_RECVERR: {e}"))
        })?;

        Ok(LinuxAsyncUdpV6Socket {
            mode: ProbeMode::UdpWithRecverr,
            destination_reached: Arc::new(AtomicBool::new(false)),
            pending_count: Arc::new(AtomicUsize::new(0)),
            dest_port: UDP_DEST_PORT,
        })
    }
}

impl ProbeSocket for LinuxAsyncUdpV6Socket {
    fn mode(&self) -> ProbeMode {
        self.mode
    }

    fn send_probe_and_recv(
        &self,
        dest: IpAddr,
        probe: ProbeInfo,
    ) -> Pin<Box<dyn Future<Output = Result<ProbeResponse, TracerouteError>> + Send + '_>> {
        Box::pin(async move {
            require_v6(dest)?;
            self.pending_count.fetch_add(1, Ordering::Relaxed);

            // Fresh UDP6 socket per probe: any error on this socket's
            // errqueue must be for this probe, so no id/seq demux needed
            // (same per-probe-socket design as the IPv4 UDP mode).
            let socket =
                Socket2::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP)).map_err(|e| {
                    self.pending_count.fetch_sub(1, Ordering::Relaxed);
                    TracerouteError::SocketError(format!("Failed to create UDP6 socket: {e}"))
                })?;

            let setup = (|| -> Result<(), TracerouteError> {
                socket
                    .bind(&SockAddr::from(SocketAddrV6::new(
                        Ipv6Addr::UNSPECIFIED,
                        0,
                        0,
                        0,
                    )))
                    .map_err(|e| {
                        TracerouteError::SocketError(format!("Failed to bind UDP6 socket: {e}"))
                    })?;
                socket.set_unicast_hops_v6(probe.ttl as u32).map_err(|e| {
                    TracerouteError::SocketError(format!("Failed to set IPV6_UNICAST_HOPS: {e}"))
                })?;
                set_recverr_v6(socket.as_raw_fd()).map_err(|e| {
                    TracerouteError::SocketError(format!("Failed to set IPV6_RECVERR: {e}"))
                })?;
                socket.set_nonblocking(true).map_err(|e| {
                    TracerouteError::SocketError(format!("Failed to set non-blocking: {e}"))
                })?;
                Ok(())
            })();
            if let Err(e) = setup {
                self.pending_count.fetch_sub(1, Ordering::Relaxed);
                return Err(e);
            }

            // Convert to a Tokio socket (keeps the fd alive in the task).
            let async_socket = UdpSocket::from_std(socket.into()).map_err(|e| {
                self.pending_count.fetch_sub(1, Ordering::Relaxed);
                TracerouteError::SocketError(format!("Failed to convert to async socket: {e}"))
            })?;

            // Connect to the destination on the traceroute port.
            let target_addr = SocketAddr::new(dest, self.dest_port);
            async_socket.connect(target_addr).await.map_err(|e| {
                self.pending_count.fetch_sub(1, Ordering::Relaxed);
                TracerouteError::SocketError(format!("Failed to connect to destination: {e}"))
            })?;

            // Payload mirrors the IPv4 UDP mode: identifier + sequence up
            // front (useful when eyeballing captures), fixed padding after.
            let identifier = std::process::id() as u16;
            let mut payload = Vec::with_capacity(32);
            payload.extend_from_slice(&identifier.to_be_bytes());
            payload.extend_from_slice(&probe.sequence.to_be_bytes());
            payload.extend_from_slice(b"ftr-traceroute-probe-padding");

            let sent_at = Instant::now();
            async_socket.send(&payload).await.map_err(|e| {
                self.pending_count.fetch_sub(1, Ordering::Relaxed);
                TracerouteError::SocketError(format!("Failed to send UDP6 probe: {e}"))
            })?;

            let destination_reached = self.destination_reached.clone();
            let pending_count = self.pending_count.clone();
            let sequence = probe.sequence;
            let ttl = probe.ttl;

            let (tx, rx) = oneshot::channel();
            let fd = async_socket.as_raw_fd();

            // Poll the error queue for the ICMPv6 answer, mirroring the
            // IPv4 task structure.
            tokio::spawn(async move {
                // Keep the socket (and its fd) alive for the whole poll.
                let _socket_guard = async_socket;
                let mut retry_count = 0;

                loop {
                    match check_errqueue_v6(fd) {
                        ErrqueueCheck::Found(err) if err.ee_origin == SO_EE_ORIGIN_ICMP6 => {
                            // The offender sockaddr carries the router that
                            // generated the error; without it the hop cannot
                            // be attributed, so keep polling.
                            if let Some((offender, _scope_id)) = err.offender {
                                let rtt = Instant::now().duration_since(sent_at);
                                let is_destination =
                                    is_v6_destination_error(err.ee_type, err.ee_code);

                                if is_destination {
                                    destination_reached.store(true, Ordering::Relaxed);
                                }
                                pending_count.fetch_sub(1, Ordering::Relaxed);

                                let _ = tx.send(ProbeResponse {
                                    from_addr: IpAddr::V6(offender),
                                    sequence,
                                    ttl,
                                    rtt,
                                    received_at: Instant::now(),
                                    is_destination,
                                    is_timeout: false,
                                });
                                break;
                            }
                        }
                        ErrqueueCheck::Found(_) => {
                            // Non-ICMPv6 origin (e.g. local errors): not a
                            // hop answer; keep polling.
                        }
                        ErrqueueCheck::Error => {
                            pending_count.fetch_sub(1, Ordering::Relaxed);
                            break;
                        }
                        ErrqueueCheck::NoData => {}
                    }

                    retry_count += 1;
                    if retry_count >= MAX_RETRIES {
                        pending_count.fetch_sub(1, Ordering::Relaxed);
                        let _ = tx.send(ProbeResponse {
                            from_addr: dest,
                            sequence,
                            ttl,
                            rtt: Duration::from_secs(1),
                            received_at: Instant::now(),
                            is_destination: false,
                            is_timeout: true,
                        });
                        break;
                    }

                    tokio::time::sleep(POLL_INTERVAL).await;
                }
            });

            match rx.await {
                Ok(response) => Ok(response),
                Err(_) => {
                    self.pending_count.fetch_sub(1, Ordering::Relaxed);
                    Err(TracerouteError::SocketError(
                        "Failed to receive response".to_string(),
                    ))
                }
            }
        })
    }

    fn destination_reached(&self) -> bool {
        self.destination_reached.load(Ordering::Relaxed)
    }

    fn pending_count(&self) -> usize {
        self.pending_count.load(Ordering::Relaxed)
    }
}

/// Async ICMPv6 ping-socket implementation (unprivileged where
/// `net.ipv4.ping_group_range` permits).
///
/// Two kernel behaviors shape this mode (both spike-validated on kernel
/// 6.8, opposite of Darwin):
///
/// 1. The kernel REWRITES the echo identifier to a per-socket value — the
///    session cannot choose one, so the id field is sent as 0 and matching
///    is by **sequence number only**, which is safe because the kernel
///    demuxes replies per-socket by its assigned ident.
/// 2. Echo replies arrive on the normal receive path, but Time Exceeded /
///    Destination Unreachable arrive ONLY via the error queue
///    (`IPV6_RECVERR` + `MSG_ERRQUEUE`) and are dropped entirely without
///    `IPV6_RECVERR`.
pub struct LinuxAsyncPingV6Socket {
    destination_reached: Arc<AtomicBool>,
    pending_count: Arc<AtomicUsize>,
}

impl LinuxAsyncPingV6Socket {
    /// Create a new ICMPv6 ping-socket handle with timing configuration.
    /// Fails with a permission error when `net.ipv4.ping_group_range`
    /// (which gates ICMPv6 ping sockets too, despite the name) excludes
    /// this process's gid — the kernel default `1 0` disables them for
    /// everyone.
    pub fn new_with_config(_timing_config: crate::TimingConfig) -> Result<Self, TracerouteError> {
        // Probe availability at creation time so the factory can fall
        // through (EACCES when ping_group_range excludes our gid).
        Socket2::new(Domain::IPV6, Type::DGRAM, Some(Protocol::ICMPV6)).map_err(|e| {
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                TracerouteError::InsufficientPermissions {
                    required: "net.ipv4.ping_group_range covering this gid".to_string(),
                    suggestion: "sudo sysctl -w net.ipv4.ping_group_range=\"0 2147483647\""
                        .to_string(),
                }
            } else {
                TracerouteError::SocketError(format!("Failed to create ICMPv6 ping socket: {e}"))
            }
        })?;

        Ok(LinuxAsyncPingV6Socket {
            destination_reached: Arc::new(AtomicBool::new(false)),
            pending_count: Arc::new(AtomicUsize::new(0)),
        })
    }
}

impl ProbeSocket for LinuxAsyncPingV6Socket {
    fn mode(&self) -> ProbeMode {
        ProbeMode::DgramIcmpv6
    }

    fn send_probe_and_recv(
        &self,
        dest: IpAddr,
        probe: ProbeInfo,
    ) -> Pin<Box<dyn Future<Output = Result<ProbeResponse, TracerouteError>> + Send + '_>> {
        Box::pin(async move {
            let dest_v6 = require_v6(dest)?;
            self.pending_count.fetch_add(1, Ordering::Relaxed);

            let result = async {
                // Fresh ping socket per probe: per-probe hop limit without
                // cross-probe races, and the kernel's per-socket demux
                // means every echo reply on it is ours.
                let socket = Socket2::new(Domain::IPV6, Type::DGRAM, Some(Protocol::ICMPV6))
                    .map_err(|e| {
                        TracerouteError::SocketError(format!(
                            "Failed to create ICMPv6 ping socket: {e}"
                        ))
                    })?;
                socket.set_unicast_hops_v6(probe.ttl as u32).map_err(|e| {
                    TracerouteError::SocketError(format!("Failed to set IPV6_UNICAST_HOPS: {e}"))
                })?;
                // Errqueue is the ONLY channel Time Exceeded arrives on for
                // ping sockets (spike-validated).
                set_recverr_v6(socket.as_raw_fd()).map_err(|e| {
                    TracerouteError::SocketError(format!("Failed to set IPV6_RECVERR: {e}"))
                })?;
                socket.set_nonblocking(true).map_err(|e| {
                    TracerouteError::SocketError(format!("Failed to set non-blocking: {e}"))
                })?;
                // No ICMP6_FILTER here: ping sockets reject it with
                // ENOPROTOOPT, and the kernel demux makes it unnecessary.

                // Identifier 0 documents that we do NOT choose one — the
                // kernel rewrites it to the socket's assigned ident on the
                // wire (spike-validated; readable via getsockname if ever
                // needed for diagnostics).
                let mut payload = [0u8; 16];
                let tag = b"ftr-traceroute";
                payload[..tag.len()].copy_from_slice(tag);
                let pkt = icmpv6::build_echo_request_v6(0, probe.sequence, &payload);

                let dest_sockaddr = SockAddr::from(SocketAddrV6::new(dest_v6, 0, 0, 0));
                let sent_at = Instant::now();
                socket.send_to(&pkt, &dest_sockaddr).map_err(|e| {
                    TracerouteError::ProbeSendError(format!("Failed to send ICMPv6 echo: {e}"))
                })?;

                Ok::<_, TracerouteError>((socket, sent_at))
            }
            .await;

            let (socket, sent_at) = match result {
                Ok(pair) => pair,
                Err(e) => {
                    self.pending_count.fetch_sub(1, Ordering::Relaxed);
                    return Err(e);
                }
            };

            let destination_reached = self.destination_reached.clone();
            let pending_count = self.pending_count.clone();
            let sequence = probe.sequence;
            let ttl = probe.ttl;

            let (tx, rx) = oneshot::channel();

            tokio::spawn(async move {
                let fd = socket.as_raw_fd();
                let mut retry_count = 0;

                loop {
                    // 1) Normal receive path: echo replies only (the kernel
                    // never delivers ICMPv6 errors here for ping sockets).
                    let mut buf = [std::mem::MaybeUninit::uninit(); RECV_BUFFER_SIZE];
                    match socket.recv_from(&mut buf) {
                        Ok((size, from)) => {
                            // SAFETY: recv_from initialized the first
                            // `size` bytes of buf.
                            let data = unsafe {
                                std::slice::from_raw_parts(buf.as_ptr().cast::<u8>(), size)
                            };
                            if let Some((_kernel_id, reply_seq)) = icmpv6::parse_echo_reply_v6(data)
                            {
                                // The identifier is the kernel-assigned
                                // per-socket ident (not ours to check);
                                // per-socket demux + per-probe socket means
                                // a matching sequence is our answer.
                                if reply_seq == sequence {
                                    let from_ip =
                                        from.as_socket_ipv6().map(|sa| *sa.ip()).unwrap_or(dest_v6);
                                    let rtt = Instant::now().duration_since(sent_at);
                                    let is_destination = from_ip == dest_v6;
                                    if is_destination {
                                        destination_reached.store(true, Ordering::Relaxed);
                                    }
                                    pending_count.fetch_sub(1, Ordering::Relaxed);
                                    let _ = tx.send(ProbeResponse {
                                        from_addr: IpAddr::V6(from_ip),
                                        sequence,
                                        ttl,
                                        rtt,
                                        received_at: Instant::now(),
                                        is_destination,
                                        is_timeout: false,
                                    });
                                    break;
                                }
                            }
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                        Err(_) => {
                            pending_count.fetch_sub(1, Ordering::Relaxed);
                            break;
                        }
                    }

                    // 2) Error queue: Time Exceeded / Destination
                    // Unreachable from intermediate routers.
                    match check_errqueue_v6(fd) {
                        ErrqueueCheck::Found(err) if err.ee_origin == SO_EE_ORIGIN_ICMP6 => {
                            if let Some((offender, _scope_id)) = err.offender {
                                let rtt = Instant::now().duration_since(sent_at);
                                pending_count.fetch_sub(1, Ordering::Relaxed);
                                // Echo probes signal destination via the
                                // echo reply above; errqueue messages are
                                // intermediate-hop errors (mirroring the
                                // IPv4 raw path's TE/unreachable handling).
                                let _ = tx.send(ProbeResponse {
                                    from_addr: IpAddr::V6(offender),
                                    sequence,
                                    ttl,
                                    rtt,
                                    received_at: Instant::now(),
                                    is_destination: false,
                                    is_timeout: false,
                                });
                                break;
                            }
                        }
                        ErrqueueCheck::Found(_) => {}
                        ErrqueueCheck::Error => {
                            pending_count.fetch_sub(1, Ordering::Relaxed);
                            break;
                        }
                        ErrqueueCheck::NoData => {}
                    }

                    retry_count += 1;
                    if retry_count >= MAX_RETRIES {
                        pending_count.fetch_sub(1, Ordering::Relaxed);
                        let _ = tx.send(ProbeResponse {
                            from_addr: dest,
                            sequence,
                            ttl,
                            rtt: Duration::from_secs(1),
                            received_at: Instant::now(),
                            is_destination: false,
                            is_timeout: true,
                        });
                        break;
                    }

                    tokio::time::sleep(POLL_INTERVAL).await;
                }
            });

            match rx.await {
                Ok(response) => Ok(response),
                Err(_) => {
                    self.pending_count.fetch_sub(1, Ordering::Relaxed);
                    Err(TracerouteError::SocketError(
                        "Failed to receive response".to_string(),
                    ))
                }
            }
        })
    }

    fn destination_reached(&self) -> bool {
        self.destination_reached.load(Ordering::Relaxed)
    }

    fn pending_count(&self) -> usize {
        self.pending_count.load(Ordering::Relaxed)
    }
}

/// Async raw ICMPv6 socket (requires root or `CAP_NET_RAW`), mirroring the
/// IPv4 [`super::linux::LinuxAsyncIcmpSocket`]. Unlike ping sockets, Time
/// Exceeded arrives on the raw socket's NORMAL receive path (no errqueue
/// needed) and the received buffer starts at the ICMPv6 header — both
/// spike-validated. Raw sockets see all inbound ICMPv6, so userspace
/// identifier + sequence (+ embedded destination) matching is mandatory.
pub struct LinuxAsyncRawIcmpV6Socket {
    icmp_identifier: u16,
    destination_reached: Arc<AtomicBool>,
    pending_count: Arc<AtomicUsize>,
}

impl LinuxAsyncRawIcmpV6Socket {
    /// Create a new raw ICMPv6 socket handle with timing configuration.
    pub fn new_with_config(_timing_config: crate::TimingConfig) -> Result<Self, TracerouteError> {
        // Probe raw-socket availability up front so permission problems
        // surface as a typed error at setup time, not on the first probe.
        Socket2::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6)).map_err(|e| {
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                TracerouteError::InsufficientPermissions {
                    required: "root or CAP_NET_RAW".to_string(),
                    suggestion: "Run with sudo, or use the default UDP mode".to_string(),
                }
            } else {
                TracerouteError::SocketError(format!("Failed to create raw ICMPv6 socket: {e}"))
            }
        })?;

        Ok(LinuxAsyncRawIcmpV6Socket {
            // Same per-process identifier scheme as the IPv4 raw mode.
            icmp_identifier: std::process::id() as u16,
            destination_reached: Arc::new(AtomicBool::new(false)),
            pending_count: Arc::new(AtomicUsize::new(0)),
        })
    }

    /// Parse one received ICMPv6 packet (buffer starts AT the ICMPv6
    /// header) against this probe's id/seq. Returns `(from, is_destination)`
    /// or `None` for foreign/noise packets, which are silently skipped.
    fn parse_raw_response(
        icmp_identifier: u16,
        data: &[u8],
        from_addr: Ipv6Addr,
        sequence: u16,
        dest: Ipv6Addr,
    ) -> Option<(Ipv6Addr, bool)> {
        let hdr = icmpv6::parse_icmpv6_header(data)?;
        if icmpv6::is_ndp(hdr.icmpv6_type) {
            return None; // RS/RA/NS/NA/Redirect link chatter
        }

        match hdr.icmpv6_type {
            icmpv6::ICMPV6_ECHO_REPLY => {
                let (reply_id, reply_seq) = icmpv6::parse_echo_reply_v6(data)?;
                if reply_id == icmp_identifier && reply_seq == sequence {
                    return Some((from_addr, true));
                }
            }
            icmpv6::ICMPV6_TIME_EXCEEDED | icmpv6::ICMPV6_DEST_UNREACHABLE => {
                let embedded = icmpv6::parse_embedded_probe(data)?;
                // The embedded destination check guards against id/seq
                // collisions with other flows (same contract as macOS).
                if embedded.identifier == icmp_identifier
                    && embedded.sequence == sequence
                    && embedded.destination == dest
                {
                    return Some((from_addr, false));
                }
            }
            _ => {}
        }
        None
    }
}

impl ProbeSocket for LinuxAsyncRawIcmpV6Socket {
    fn mode(&self) -> ProbeMode {
        ProbeMode::RawIcmp
    }

    fn send_probe_and_recv(
        &self,
        dest: IpAddr,
        probe: ProbeInfo,
    ) -> Pin<Box<dyn Future<Output = Result<ProbeResponse, TracerouteError>> + Send + '_>> {
        Box::pin(async move {
            let dest_v6 = require_v6(dest)?;
            self.pending_count.fetch_add(1, Ordering::Relaxed);

            let result = (|| {
                let socket = Socket2::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6))
                    .map_err(|e| {
                        TracerouteError::SocketError(format!(
                            "Failed to create raw ICMPv6 socket: {e}"
                        ))
                    })?;
                socket.set_unicast_hops_v6(probe.ttl as u32).map_err(|e| {
                    TracerouteError::SocketError(format!("Failed to set IPV6_UNICAST_HOPS: {e}"))
                })?;
                socket.set_nonblocking(true).map_err(|e| {
                    TracerouteError::SocketError(format!("Failed to set non-blocking: {e}"))
                })?;
                // Best-effort kernel-side noise shedding (Linux inverted
                // bit=BLOCK semantics); userspace matching stays mandatory.
                apply_icmp6_filter_raw(socket.as_raw_fd());

                // Checksum stays zero: the kernel computes it on raw
                // ICMPv6 sends too (spike-validated).
                let mut payload = [0u8; 16];
                let tag = b"ftr-traceroute";
                payload[..tag.len()].copy_from_slice(tag);
                let pkt =
                    icmpv6::build_echo_request_v6(self.icmp_identifier, probe.sequence, &payload);

                let dest_sockaddr = SockAddr::from(SocketAddrV6::new(dest_v6, 0, 0, 0));
                let sent_at = Instant::now();
                socket.send_to(&pkt, &dest_sockaddr).map_err(|e| {
                    TracerouteError::ProbeSendError(format!("Failed to send ICMPv6 packet: {e}"))
                })?;
                Ok::<_, TracerouteError>((socket, sent_at))
            })();

            let (socket, sent_at) = match result {
                Ok(pair) => pair,
                Err(e) => {
                    self.pending_count.fetch_sub(1, Ordering::Relaxed);
                    return Err(e);
                }
            };

            let destination_reached = self.destination_reached.clone();
            let pending_count = self.pending_count.clone();
            let sequence = probe.sequence;
            let ttl = probe.ttl;
            let icmp_identifier = self.icmp_identifier;

            let (tx, rx) = oneshot::channel();

            tokio::spawn(async move {
                let mut retry_count = 0;

                loop {
                    let mut buf = [std::mem::MaybeUninit::uninit(); RECV_BUFFER_SIZE];
                    match socket.recv_from(&mut buf) {
                        Ok((size, from)) => {
                            if let Some(from_sa) = from.as_socket_ipv6() {
                                // SAFETY: recv_from initialized the first
                                // `size` bytes of buf.
                                let data = unsafe {
                                    std::slice::from_raw_parts(buf.as_ptr().cast::<u8>(), size)
                                };
                                if let Some((resp_addr, is_destination)) =
                                    LinuxAsyncRawIcmpV6Socket::parse_raw_response(
                                        icmp_identifier,
                                        data,
                                        *from_sa.ip(),
                                        sequence,
                                        dest_v6,
                                    )
                                {
                                    let rtt = Instant::now().duration_since(sent_at);
                                    if is_destination {
                                        destination_reached.store(true, Ordering::Relaxed);
                                    }
                                    pending_count.fetch_sub(1, Ordering::Relaxed);
                                    let _ = tx.send(ProbeResponse {
                                        from_addr: IpAddr::V6(resp_addr),
                                        sequence,
                                        ttl,
                                        rtt,
                                        received_at: Instant::now(),
                                        is_destination,
                                        is_timeout: false,
                                    });
                                    break;
                                }
                            }
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                        Err(_) => {
                            pending_count.fetch_sub(1, Ordering::Relaxed);
                            break;
                        }
                    }

                    retry_count += 1;
                    if retry_count >= MAX_RETRIES {
                        pending_count.fetch_sub(1, Ordering::Relaxed);
                        let _ = tx.send(ProbeResponse {
                            from_addr: dest,
                            sequence,
                            ttl,
                            rtt: Duration::from_secs(1),
                            received_at: Instant::now(),
                            is_destination: false,
                            is_timeout: true,
                        });
                        break;
                    }

                    tokio::time::sleep(POLL_INTERVAL).await;
                }
            });

            match rx.await {
                Ok(response) => Ok(response),
                Err(_) => {
                    self.pending_count.fetch_sub(1, Ordering::Relaxed);
                    Err(TracerouteError::SocketError(
                        "Failed to receive response".to_string(),
                    ))
                }
            }
        })
    }

    fn destination_reached(&self) -> bool {
        self.destination_reached.load(Ordering::Relaxed)
    }

    fn pending_count(&self) -> usize {
        self.pending_count.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a synthetic IPV6_RECVERR cmsg payload: a native-endian
    /// `sock_extended_err` optionally followed by an `AF_INET6`
    /// `sockaddr_in6` offender, mirroring what the kernel writes.
    fn build_payload(
        ee_errno: u32,
        ee_origin: u8,
        ee_type: u8,
        ee_code: u8,
        offender: Option<(Ipv6Addr, u32)>,
        offender_family: u16,
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&ee_errno.to_ne_bytes());
        buf.extend_from_slice(&[ee_origin, ee_type, ee_code, 0 /* ee_pad */]);
        buf.extend_from_slice(&0u32.to_ne_bytes()); // ee_info
        buf.extend_from_slice(&0u32.to_ne_bytes()); // ee_data
        assert_eq!(buf.len(), SOCK_EXTENDED_ERR_SIZE);
        if let Some((addr, scope_id)) = offender {
            let mut sa = vec![0u8; SOCKADDR_IN6_SIZE];
            sa[0..2].copy_from_slice(&offender_family.to_ne_bytes());
            // sin6_port/sin6_flowinfo left zero (kernel zeroes them too)
            sa[SIN6_ADDR_OFFSET..SIN6_ADDR_OFFSET + 16].copy_from_slice(&addr.octets());
            sa[SIN6_SCOPE_ID_OFFSET..SIN6_SCOPE_ID_OFFSET + 4]
                .copy_from_slice(&scope_id.to_ne_bytes());
            buf.extend_from_slice(&sa);
        }
        buf
    }

    /// The hop-2 router observed live on trogdor (docs/IPV6_DESIGN.md).
    const HOP_ROUTER: Ipv6Addr = Ipv6Addr::new(0x2001, 0x5a8, 0x657, 0x21, 0, 0, 0xf0, 4);
    const GOOGLE_V6: Ipv6Addr = Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888);

    #[test]
    fn test_parse_recverr_time_exceeded() {
        // Exactly what the spike observed for an expired hop: ee_errno=113
        // (EHOSTUNREACH), origin ICMP6, type 3, code 0, offender = router.
        let payload = build_payload(
            113,
            SO_EE_ORIGIN_ICMP6,
            icmpv6::ICMPV6_TIME_EXCEEDED,
            0,
            Some((HOP_ROUTER, 0)),
            libc::AF_INET6 as u16,
        );
        let err = parse_recverr_payload(&payload).expect("valid TE payload must parse");
        assert_eq!(err.ee_errno, 113);
        assert_eq!(err.ee_origin, SO_EE_ORIGIN_ICMP6);
        assert_eq!(err.ee_type, icmpv6::ICMPV6_TIME_EXCEEDED);
        assert_eq!(err.ee_code, 0);
        assert_eq!(err.offender, Some((HOP_ROUTER, 0)));
        assert!(!is_v6_destination_error(err.ee_type, err.ee_code));
    }

    #[test]
    fn test_parse_recverr_destination_port_unreachable() {
        // The destination-reached signal: ee_errno=111 (ECONNREFUSED),
        // type 1, code 4 (spike hop 15).
        let payload = build_payload(
            111,
            SO_EE_ORIGIN_ICMP6,
            icmpv6::ICMPV6_DEST_UNREACHABLE,
            ICMPV6_UNREACH_PORT,
            Some((GOOGLE_V6, 0)),
            libc::AF_INET6 as u16,
        );
        let err = parse_recverr_payload(&payload).expect("valid unreachable payload must parse");
        assert_eq!(err.offender, Some((GOOGLE_V6, 0)));
        assert!(is_v6_destination_error(err.ee_type, err.ee_code));
        // Other unreachable codes are NOT the destination signal.
        assert!(!is_v6_destination_error(icmpv6::ICMPV6_DEST_UNREACHABLE, 0));
        assert!(!is_v6_destination_error(icmpv6::ICMPV6_TIME_EXCEEDED, 4));
    }

    #[test]
    fn test_parse_recverr_offender_scope_id_preserved() {
        // A link-local offender must keep its zone (RFC 4007) — scope 3.
        let ll = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let payload = build_payload(
            113,
            SO_EE_ORIGIN_ICMP6,
            icmpv6::ICMPV6_TIME_EXCEEDED,
            0,
            Some((ll, 3)),
            libc::AF_INET6 as u16,
        );
        let err = parse_recverr_payload(&payload).expect("must parse");
        assert_eq!(err.offender, Some((ll, 3)));
    }

    #[test]
    fn test_parse_recverr_no_offender() {
        // sock_extended_err alone (no SO_EE_OFFENDER sockaddr appended).
        let payload = build_payload(111, SO_EE_ORIGIN_ICMP6, 1, 4, None, 0);
        let err = parse_recverr_payload(&payload).expect("must parse without offender");
        assert_eq!(err.offender, None);
    }

    #[test]
    fn test_parse_recverr_wrong_family_offender_ignored() {
        // An offender sockaddr that is not AF_INET6 must not be
        // misinterpreted as an IPv6 address.
        let payload = build_payload(
            113,
            SO_EE_ORIGIN_ICMP6,
            icmpv6::ICMPV6_TIME_EXCEEDED,
            0,
            Some((HOP_ROUTER, 0)),
            libc::AF_INET as u16,
        );
        let err = parse_recverr_payload(&payload).expect("must parse");
        assert_eq!(err.offender, None);
    }

    #[test]
    fn test_parse_recverr_truncated() {
        let payload = build_payload(113, SO_EE_ORIGIN_ICMP6, 3, 0, None, 0);
        assert!(parse_recverr_payload(&payload[..SOCK_EXTENDED_ERR_SIZE - 1]).is_none());
        assert!(parse_recverr_payload(&[]).is_none());
    }

    #[test]
    fn test_parse_recverr_non_icmp6_origin_still_parses() {
        // Origin filtering is the caller's job (the poll loops check
        // ee_origin); the parser just reports fields faithfully.
        let payload = build_payload(101, 1 /* SO_EE_ORIGIN_LOCAL */, 0, 0, None, 0);
        let err = parse_recverr_payload(&payload).expect("must parse");
        assert_eq!(err.ee_origin, 1);
        assert_ne!(err.ee_origin, SO_EE_ORIGIN_ICMP6);
    }

    #[test]
    fn test_icmp6_filter_linux_inverted_semantics() {
        // Linux: bit SET = BLOCK. block_all() sets every bit; pass()
        // clears exactly the requested types.
        let filter = Icmp6FilterLinux::block_all()
            .pass(icmpv6::ICMPV6_DEST_UNREACHABLE)
            .pass(icmpv6::ICMPV6_TIME_EXCEEDED)
            .pass(icmpv6::ICMPV6_ECHO_REPLY);
        assert!(filter.passes(icmpv6::ICMPV6_DEST_UNREACHABLE));
        assert!(filter.passes(icmpv6::ICMPV6_TIME_EXCEEDED));
        assert!(filter.passes(icmpv6::ICMPV6_ECHO_REPLY));
        // Echo Request and NDP chatter stay blocked (bit set).
        assert!(!filter.passes(icmpv6::ICMPV6_ECHO_REQUEST));
        for ty in 133..=137u8 {
            assert!(!filter.passes(ty), "NDP type {ty} must remain blocked");
        }
    }

    #[test]
    fn test_parse_raw_response_demux() {
        let id = 0x4242u16;
        let seq = 9u16;

        // Own echo reply: matches, is destination.
        let mut reply = icmpv6::build_echo_request_v6(id, seq, &[]);
        reply[0] = icmpv6::ICMPV6_ECHO_REPLY;
        assert_eq!(
            LinuxAsyncRawIcmpV6Socket::parse_raw_response(id, &reply, GOOGLE_V6, seq, GOOGLE_V6),
            Some((GOOGLE_V6, true))
        );

        // Foreign identifier: skipped (raw sockets see everything).
        let mut foreign = icmpv6::build_echo_request_v6(0x9999, seq, &[]);
        foreign[0] = icmpv6::ICMPV6_ECHO_REPLY;
        assert_eq!(
            LinuxAsyncRawIcmpV6Socket::parse_raw_response(id, &foreign, GOOGLE_V6, seq, GOOGLE_V6),
            None
        );

        // Time Exceeded embedding our probe: matches, not destination.
        let mut te = vec![0u8; 56];
        te[0] = icmpv6::ICMPV6_TIME_EXCEEDED;
        te[8] = 6 << 4; // embedded IPv6 version
        te[14] = icmpv6::IPV6_NEXT_HEADER_ICMPV6;
        te[32..48].copy_from_slice(&GOOGLE_V6.octets());
        te[48] = icmpv6::ICMPV6_ECHO_REQUEST;
        te[52..54].copy_from_slice(&id.to_be_bytes());
        te[54..56].copy_from_slice(&seq.to_be_bytes());
        assert_eq!(
            LinuxAsyncRawIcmpV6Socket::parse_raw_response(id, &te, HOP_ROUTER, seq, GOOGLE_V6),
            Some((HOP_ROUTER, false))
        );

        // Same id/seq but wrong embedded destination: another flow.
        let other = Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111);
        let mut wrong_dst = te.clone();
        wrong_dst[32..48].copy_from_slice(&other.octets());
        assert_eq!(
            LinuxAsyncRawIcmpV6Socket::parse_raw_response(
                id, &wrong_dst, HOP_ROUTER, seq, GOOGLE_V6
            ),
            None
        );

        // NDP noise: skipped.
        let ra = [134u8, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(
            LinuxAsyncRawIcmpV6Socket::parse_raw_response(id, &ra, HOP_ROUTER, seq, GOOGLE_V6),
            None
        );
    }
}
