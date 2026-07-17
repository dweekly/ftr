//! macOS async ICMPv6 socket using per-probe DGRAM sockets
//!
//! Unprivileged IPv6 traceroute: `Domain::IPV6`/`Type::DGRAM`/
//! `Protocol::ICMPV6` sockets work without root on Darwin and receive
//! ICMPv6 Time Exceeded from intermediate routers on the normal receive
//! path — both validated live by `examples/spike_traceroute6.rs` (findings
//! recorded in `docs/IPV6_DESIGN.md`). Mirrors the per-probe-socket design
//! of the IPv4 implementation in [`super::macos`].
//!
//! Two Darwin-specific behaviors shape this module (both spike-proven):
//!
//! 1. **No kernel demux by echo identifier.** Every DGRAM ICMPv6 socket
//!    receives ALL inbound ICMPv6 traffic — other processes' echo replies,
//!    other probes from this same trace, and NDP/RA link noise. Userspace
//!    identifier+sequence filtering is therefore mandatory for correctness,
//!    on Echo Replies AND on the embedded probe inside error messages.
//! 2. **`ICMP6_FILTER` works** (BSD semantics, bit set = PASS) and sheds the
//!    NDP noise in the kernel, but it cannot distinguish two concurrent
//!    traces' echoes, so it is applied strictly as an optimization: setup
//!    failure is logged and ignored.

use crate::TimingConfig;
use crate::probe::{ProbeInfo, ProbeResponse};
use crate::socket::icmpv6;
use crate::socket::traits::{ProbeMode, ProbeSocket};
use crate::traceroute::TracerouteError;
use socket2::{Domain, Protocol, SockAddr, Socket as Socket2, Type};
use std::future::Future;
use std::net::{IpAddr, Ipv6Addr, SocketAddrV6};
use std::os::fd::AsRawFd;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// Size of the ICMPv6 echo payload, matching the IPv4 implementation's
/// [`super::macos`] probe payload size.
const ICMPV6_ECHO_PAYLOAD_SIZE: usize = 16;

/// Receive buffer size — a full Ethernet-MTU packet comfortably fits.
const RECV_BUFFER_SIZE: usize = 1500;

/// Polling interval while waiting for a reply on the non-blocking socket,
/// matching the IPv4 macOS implementation's 1 ms poll loop.
const RECV_POLL_INTERVAL: Duration = Duration::from_millis(1);

/// `ICMP6_FILTER` socket option (level `IPPROTO_ICMPV6`). The libc crate
/// does not define it for Apple targets; the value 18 is verified against
/// the macOS SDK header `netinet6/in6.h` line 392
/// (`#define ICMP6_FILTER 18`) — same citation as the validation spike.
const ICMP6_FILTER: libc::c_int = 18;

/// Mirror of `struct icmp6_filter` (macOS SDK `netinet/icmp6.h` line 624):
/// 256 bits, one per ICMPv6 type. BSD semantics: bit SET means PASS
/// (`ICMP6_FILTER_SETPASS` ORs the bit in; `SETBLOCKALL` is memset 0).
/// Linux inverts these semantics (bit = block) — do not reuse as-is there.
#[repr(C)]
struct Icmp6Filter {
    icmp6_filt: [u32; 8],
}

impl Icmp6Filter {
    /// Start from "block everything" (all bits clear).
    fn block_all() -> Self {
        Icmp6Filter { icmp6_filt: [0; 8] }
    }

    /// Set the PASS bit for one ICMPv6 type, mirroring the
    /// `ICMP6_FILTER_SETPASS` macro: `filt[type >> 5] |= 1 << (type & 31)`.
    fn pass(mut self, ty: u8) -> Self {
        self.icmp6_filt[(ty >> 5) as usize] |= 1u32 << (ty & 31);
        self
    }
}

/// Monotonic per-process counter mixed into each socket's ICMP identifier.
///
/// Darwin does not demux ICMPv6 by identifier, so uniqueness is not about
/// kernel routing — it lets concurrent traces in one process (and, with the
/// PID component, across processes) tell their packets apart in userspace.
/// Carried-over SwiftFTR lesson recorded in `docs/IPV6_DESIGN.md`.
static NEXT_SESSION: AtomicU16 = AtomicU16::new(0);

/// Derive a fresh ICMP identifier: low byte of the PID in the high bits,
/// per-process session counter in the low bits.
fn next_identifier() -> u16 {
    let pid_component = (std::process::id() & 0xff) as u16;
    let session = NEXT_SESSION.fetch_add(1, Ordering::Relaxed) & 0xff;
    (pid_component << 8) | session
}

/// One received ICMPv6 packet plus recvmsg metadata.
struct ReceivedV6 {
    bytes_len: usize,
    /// Sender, including the sin6_scope_id zone for link-local responders —
    /// never stripped (address contract in `docs/IPV6_DESIGN.md`).
    from: SocketAddrV6,
    /// Hop limit of the received packet from the `IPV6_HOPLIMIT` cmsg
    /// (requires `IPV6_RECVHOPLIMIT`; used for verbose diagnostics).
    hop_limit: Option<u32>,
}

/// Receive one datagram with `libc::recvmsg` so the `IPV6_HOPLIMIT`
/// ancillary data is readable (socket2 0.6 exposes `recvmsg` but no cmsg
/// parser). Returns `Ok(None)` when the non-blocking socket has nothing
/// pending (EAGAIN/EWOULDBLOCK).
fn recvmsg_v6(socket: &Socket2, buf: &mut [u8]) -> std::io::Result<Option<ReceivedV6>> {
    let mut name: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
    // Space for a few cmsgs; CMSG_SPACE(4) is ~16 bytes on Darwin, 256 is
    // comfortably enough (same sizing as the validation spike).
    let mut control = [0u8; 256];
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr().cast(),
        iov_len: buf.len(),
    };
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = (&raw mut name).cast();
    msg.msg_namelen = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
    msg.msg_iov = &raw mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = control.len() as _;

    // SAFETY: all msghdr pointers reference live stack buffers above.
    let n = unsafe { libc::recvmsg(socket.as_raw_fd(), &raw mut msg, 0) };
    if n < 0 {
        let err = std::io::Error::last_os_error();
        return if err.kind() == std::io::ErrorKind::WouldBlock {
            Ok(None)
        } else {
            Err(err)
        };
    }

    let mut hop_limit = None;
    // SAFETY: cmsg iteration follows the CMSG_* contract on the msghdr that
    // recvmsg just filled in.
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(&raw const msg);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::IPPROTO_IPV6 && (*cmsg).cmsg_type == libc::IPV6_HOPLIMIT
            {
                let mut v: libc::c_int = 0;
                std::ptr::copy_nonoverlapping(
                    libc::CMSG_DATA(cmsg),
                    (&raw mut v).cast::<u8>(),
                    std::mem::size_of::<libc::c_int>(),
                );
                hop_limit = Some(v as u32);
            }
            cmsg = libc::CMSG_NXTHDR(&raw const msg, cmsg);
        }
    }

    let from = SocketAddrV6::new(
        Ipv6Addr::from(name.sin6_addr.s6_addr),
        u16::from_be(name.sin6_port),
        u32::from_be(name.sin6_flowinfo),
        name.sin6_scope_id,
    );
    Ok(Some(ReceivedV6 {
        bytes_len: n as usize,
        from,
        hop_limit,
    }))
}

/// macOS async ICMPv6 socket implementation using per-probe DGRAM sockets.
pub struct MacOSAsyncIcmpV6Socket {
    icmp_identifier: u16,
    destination_reached: Arc<AtomicBool>,
    pending_count: Arc<AtomicUsize>,
    timing_config: TimingConfig,
    verbose: u8,
}

impl MacOSAsyncIcmpV6Socket {
    /// Create a new macOS async ICMPv6 socket handle with timing
    /// configuration and an explicit verbosity level.
    pub fn new_with_config_and_verbose(
        timing_config: TimingConfig,
        verbose: u8,
    ) -> Result<Self, TracerouteError> {
        trace_time!(
            verbose,
            "Creating macOS async ICMPv6 socket (per-probe version)"
        );

        // Probe socket creation up front so permission/support problems
        // surface as a typed error at setup time, not on the first probe.
        Socket2::new(Domain::IPV6, Type::DGRAM, Some(Protocol::ICMPV6)).map_err(|e| {
            TracerouteError::SocketError(format!("Failed to create ICMPv6 DGRAM socket: {e}"))
        })?;

        Ok(Self {
            icmp_identifier: next_identifier(),
            destination_reached: Arc::new(AtomicBool::new(false)),
            pending_count: Arc::new(AtomicUsize::new(0)),
            timing_config,
            verbose,
        })
    }

    /// Apply the traceroute `ICMP6_FILTER` (pass Destination Unreachable,
    /// Time Exceeded, Echo Reply only) via raw setsockopt — socket2 exposes
    /// no API for it (<https://github.com/rust-lang/socket2/issues/199>).
    ///
    /// Best-effort: kernel-side noise shedding only. Userspace identifier
    /// filtering below is what guarantees correctness, so failure here is
    /// logged (verbose) and otherwise ignored.
    fn apply_icmp6_filter(&self, socket: &Socket2) {
        let filter = Icmp6Filter::block_all()
            .pass(icmpv6::ICMPV6_DEST_UNREACHABLE)
            .pass(icmpv6::ICMPV6_TIME_EXCEEDED)
            .pass(icmpv6::ICMPV6_ECHO_REPLY);
        // SAFETY: fd is valid for the lifetime of `socket`; the buffer is a
        // properly sized repr(C) mirror of struct icmp6_filter.
        let rc = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_ICMPV6,
                ICMP6_FILTER,
                (&raw const filter).cast(),
                std::mem::size_of::<Icmp6Filter>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            trace_time!(
                self.verbose,
                "setsockopt(ICMP6_FILTER) failed ({}); continuing with userspace filtering only",
                std::io::Error::last_os_error()
            );
        }
    }

    /// Parse one received ICMPv6 packet (buffer starts AT the ICMPv6
    /// header — no IPv6 header prefix) against this probe's id/seq.
    ///
    /// Returns `None` for anything that is not a definitive answer to this
    /// probe: NDP noise, other sessions' echoes, other sequences from this
    /// same trace. Skipping silently is correct — Darwin funnels all ICMPv6
    /// to every DGRAM socket.
    fn parse_response_v6(
        &self,
        packet: &[u8],
        received: &ReceivedV6,
        expected_sequence: u16,
        dest: Ipv6Addr,
        recv_time: Instant,
    ) -> Option<ProbeResponse> {
        let hdr = icmpv6::parse_icmpv6_header(packet)?;

        if icmpv6::is_ndp(hdr.icmpv6_type) {
            return None; // RS/RA/NS/NA/Redirect chatter
        }

        trace_time!(
            self.verbose,
            "Received ICMPv6 type {} code {} from {} (reply hop_limit {:?})",
            hdr.icmpv6_type,
            hdr.icmpv6_code,
            icmpv6::format_ipv6_with_zone(*received.from.ip(), received.from.scope_id()),
            received.hop_limit
        );

        match hdr.icmpv6_type {
            icmpv6::ICMPV6_TIME_EXCEEDED | icmpv6::ICMPV6_DEST_UNREACHABLE => {
                let embedded = icmpv6::parse_embedded_probe(packet)?;
                // Mandatory userspace demux: embedded identifier AND
                // sequence must match this probe; the embedded destination
                // guards against id/seq collisions with other flows.
                if embedded.identifier == self.icmp_identifier
                    && embedded.sequence == expected_sequence
                    && embedded.destination == dest
                {
                    let is_destination = hdr.icmpv6_type == icmpv6::ICMPV6_DEST_UNREACHABLE;
                    return Some(ProbeResponse {
                        from_addr: IpAddr::V6(*received.from.ip()),
                        sequence: expected_sequence,
                        ttl: 0, // filled by caller
                        rtt: Duration::ZERO,
                        received_at: recv_time,
                        is_destination,
                        is_timeout: false,
                    });
                }
            }
            icmpv6::ICMPV6_ECHO_REPLY => {
                if let Some((reply_id, reply_seq)) = icmpv6::parse_echo_reply_v6(packet) {
                    if reply_id == self.icmp_identifier && reply_seq == expected_sequence {
                        let from_ip = *received.from.ip();
                        return Some(ProbeResponse {
                            from_addr: IpAddr::V6(from_ip),
                            sequence: expected_sequence,
                            ttl: 0, // filled by caller
                            rtt: Duration::ZERO,
                            received_at: recv_time,
                            is_destination: from_ip == dest,
                            is_timeout: false,
                        });
                    }
                }
            }
            _ => {}
        }

        None
    }

    /// Send one hop-limited ICMPv6 echo probe and wait for its response.
    async fn send_and_recv_probe(
        &self,
        dest: Ipv6Addr,
        probe: ProbeInfo,
    ) -> Result<ProbeResponse, TracerouteError> {
        let send_start = probe.sent_at;

        // Fresh DGRAM ICMPv6 socket per probe (per-probe hop limit without
        // cross-probe races, mirroring the IPv4 implementation).
        let socket =
            Socket2::new(Domain::IPV6, Type::DGRAM, Some(Protocol::ICMPV6)).map_err(|e| {
                TracerouteError::SocketError(format!("Failed to create ICMPv6 socket: {e}"))
            })?;

        socket.set_unicast_hops_v6(probe.ttl as u32).map_err(|e| {
            TracerouteError::SocketError(format!("Failed to set IPV6_UNICAST_HOPS: {e}"))
        })?;
        socket.set_recv_hoplimit_v6(true).map_err(|e| {
            TracerouteError::SocketError(format!("Failed to set IPV6_RECVHOPLIMIT: {e}"))
        })?;
        socket.set_nonblocking(true).map_err(|e| {
            TracerouteError::SocketError(format!("Failed to set non-blocking: {e}"))
        })?;
        self.apply_icmp6_filter(&socket);

        // Payload mirrors the IPv4 path: identifier+sequence packed at the
        // front of a fixed-size payload (useful when eyeballing captures).
        let payload_data = ((self.icmp_identifier as u32) << 16) | (probe.sequence as u32);
        let mut payload = [0u8; ICMPV6_ECHO_PAYLOAD_SIZE];
        payload[..4].copy_from_slice(&payload_data.to_be_bytes());

        // Checksum stays zero: the kernel computes it on DGRAM ICMPv6 send
        // (validated — see module docs).
        let pkt = icmpv6::build_echo_request_v6(self.icmp_identifier, probe.sequence, &payload);

        let dest_sockaddr = SockAddr::from(SocketAddrV6::new(dest, 0, 0, 0));
        socket.send_to(&pkt, &dest_sockaddr).map_err(|e| {
            TracerouteError::ProbeSendError(format!("Failed to send ICMPv6 packet: {e}"))
        })?;

        trace_time!(
            self.verbose,
            "Sent ICMPv6 echo seq={} hop_limit={} to {}",
            probe.sequence,
            probe.ttl,
            dest
        );

        // Poll for a matching reply until the socket read timeout. The
        // socket sees ALL inbound ICMPv6, so keep draining and skipping
        // non-matching packets rather than stopping at the first one.
        let deadline = send_start + self.timing_config.socket_read_timeout;
        let mut buf = [0u8; RECV_BUFFER_SIZE];
        loop {
            if Instant::now() >= deadline {
                break;
            }
            match recvmsg_v6(&socket, &mut buf) {
                Ok(Some(received)) => {
                    let recv_time = Instant::now();
                    if let Some(mut response) = self.parse_response_v6(
                        &buf[..received.bytes_len],
                        &received,
                        probe.sequence,
                        dest,
                        recv_time,
                    ) {
                        response.ttl = probe.ttl;
                        response.rtt = recv_time.duration_since(send_start);
                        trace_time!(
                            self.verbose,
                            "Matched ICMPv6 response for seq={} from {} rtt={:?}",
                            probe.sequence,
                            response.from_addr,
                            response.rtt
                        );
                        if response.is_destination {
                            self.destination_reached.store(true, Ordering::Relaxed);
                        }
                        self.pending_count.fetch_sub(1, Ordering::Relaxed);
                        return Ok(response);
                    }
                    // Not ours — keep draining without sleeping.
                }
                Ok(None) => {
                    // Nothing pending; yield until the next poll tick.
                    tokio::time::sleep(RECV_POLL_INTERVAL).await;
                }
                Err(e) => {
                    trace_time!(self.verbose, "ICMPv6 recv error: {}", e);
                    break;
                }
            }
        }

        // Timeout: report it the same way the IPv4 macOS path does.
        trace_time!(
            self.verbose,
            "Timeout waiting for ICMPv6 response to seq={}",
            probe.sequence
        );
        self.pending_count.fetch_sub(1, Ordering::Relaxed);
        Ok(ProbeResponse {
            from_addr: IpAddr::V6(dest),
            sequence: probe.sequence,
            ttl: probe.ttl,
            rtt: self.timing_config.socket_read_timeout,
            received_at: Instant::now(),
            is_destination: false,
            is_timeout: true,
        })
    }
}

impl ProbeSocket for MacOSAsyncIcmpV6Socket {
    fn mode(&self) -> ProbeMode {
        ProbeMode::DgramIcmpv6
    }

    fn send_probe_and_recv(
        &self,
        dest: IpAddr,
        probe: ProbeInfo,
    ) -> Pin<Box<dyn Future<Output = Result<ProbeResponse, TracerouteError>> + Send + '_>> {
        Box::pin(async move {
            let dest_v6 = match dest {
                IpAddr::V6(addr) => addr,
                IpAddr::V4(_) => {
                    return Err(TracerouteError::SocketError(
                        "ICMPv6 socket cannot probe an IPv4 destination".to_string(),
                    ));
                }
            };

            self.pending_count.fetch_add(1, Ordering::Relaxed);
            let result = self.send_and_recv_probe(dest_v6, probe).await;
            if result.is_err() {
                // Success and timeout paths decrement inside; keep the
                // pending count honest on send/setup errors too.
                self.pending_count.fetch_sub(1, Ordering::Relaxed);
            }
            result
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

    #[test]
    fn test_next_identifier_unique_per_socket() {
        let a = next_identifier();
        let b = next_identifier();
        assert_ne!(a, b, "concurrent sockets must get distinct identifiers");
        // High byte carries the PID component for cross-process uniqueness.
        assert_eq!(a >> 8, (std::process::id() & 0xff) as u16);
        assert_eq!(a >> 8, b >> 8);
    }

    #[test]
    fn test_icmp6_filter_pass_bits() {
        // Mirror ICMP6_FILTER_SETPASS semantics for the three types the
        // traceroute filter passes.
        let filter = Icmp6Filter::block_all()
            .pass(icmpv6::ICMPV6_DEST_UNREACHABLE)
            .pass(icmpv6::ICMPV6_TIME_EXCEEDED)
            .pass(icmpv6::ICMPV6_ECHO_REPLY);
        let is_set = |ty: u8| filter.icmp6_filt[(ty >> 5) as usize] & (1u32 << (ty & 31)) != 0;
        assert!(is_set(1));
        assert!(is_set(3));
        assert!(is_set(129));
        // Everything else stays blocked, notably NDP and Echo Request.
        assert!(!is_set(128));
        for ty in 133..=137u8 {
            assert!(!is_set(ty), "NDP type {ty} must remain blocked");
        }
    }

    /// The parser must ignore foreign identifiers, NDP noise, and wrong
    /// sequences — the userspace demux contract.
    #[test]
    fn test_parse_response_v6_filters_foreign_traffic() {
        let sock = MacOSAsyncIcmpV6Socket {
            icmp_identifier: 0x4242,
            destination_reached: Arc::new(AtomicBool::new(false)),
            pending_count: Arc::new(AtomicUsize::new(0)),
            timing_config: TimingConfig::default(),
            verbose: 0,
        };
        let dest = Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888);
        let received = ReceivedV6 {
            bytes_len: 0,
            from: SocketAddrV6::new(dest, 0, 0, 0),
            hop_limit: Some(64),
        };
        let now = Instant::now();

        // Own echo reply matches and is the destination.
        let mut own_reply = icmpv6::build_echo_request_v6(0x4242, 7, &[]);
        own_reply[0] = icmpv6::ICMPV6_ECHO_REPLY;
        let resp = sock
            .parse_response_v6(&own_reply, &received, 7, dest, now)
            .expect("own echo reply must match");
        assert!(resp.is_destination);
        assert_eq!(resp.from_addr, IpAddr::V6(dest));

        // Foreign identifier: skipped.
        let mut foreign = icmpv6::build_echo_request_v6(0x9999, 7, &[]);
        foreign[0] = icmpv6::ICMPV6_ECHO_REPLY;
        assert!(
            sock.parse_response_v6(&foreign, &received, 7, dest, now)
                .is_none()
        );

        // Own identifier, wrong sequence (another probe of this trace): skipped.
        let mut wrong_seq = icmpv6::build_echo_request_v6(0x4242, 8, &[]);
        wrong_seq[0] = icmpv6::ICMPV6_ECHO_REPLY;
        assert!(
            sock.parse_response_v6(&wrong_seq, &received, 7, dest, now)
                .is_none()
        );

        // NDP noise (Router Advertisement): skipped.
        let ra = [134u8, 0, 0, 0, 0x40, 0xc8, 0x07, 0x08];
        assert!(
            sock.parse_response_v6(&ra, &received, 7, dest, now)
                .is_none()
        );
    }

    /// Time Exceeded demux: embedded id+seq+destination must all match.
    #[test]
    fn test_parse_response_v6_time_exceeded_demux() {
        let sock = MacOSAsyncIcmpV6Socket {
            icmp_identifier: 0x4242,
            destination_reached: Arc::new(AtomicBool::new(false)),
            pending_count: Arc::new(AtomicUsize::new(0)),
            timing_config: TimingConfig::default(),
            verbose: 0,
        };
        let dest = Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888);
        let hop = Ipv6Addr::new(0x2001, 0x5a8, 5, 0x403f, 0, 0, 0xf0, 2);
        let received = ReceivedV6 {
            bytes_len: 0,
            from: SocketAddrV6::new(hop, 0, 0, 0),
            hop_limit: Some(62),
        };
        let now = Instant::now();

        // Synthesize the TE a router would send for our probe (layout
        // matches the live capture in docs/IPV6_DESIGN.md).
        let build_te = |id: u16, seq: u16, embedded_dst: Ipv6Addr| {
            let mut buf = vec![0u8; 56];
            buf[0] = icmpv6::ICMPV6_TIME_EXCEEDED;
            buf[8] = 6 << 4; // embedded IPv6 version
            buf[14] = icmpv6::IPV6_NEXT_HEADER_ICMPV6; // embedded next header
            buf[32..48].copy_from_slice(&embedded_dst.octets());
            buf[48] = icmpv6::ICMPV6_ECHO_REQUEST;
            buf[52..54].copy_from_slice(&id.to_be_bytes());
            buf[54..56].copy_from_slice(&seq.to_be_bytes());
            buf
        };

        let te = build_te(0x4242, 3, dest);
        let resp = sock
            .parse_response_v6(&te, &received, 3, dest, now)
            .expect("matching TE must parse");
        assert!(!resp.is_destination);
        assert_eq!(resp.from_addr, IpAddr::V6(hop));

        // Foreign embedded identifier: someone else's expired probe.
        let foreign_te = build_te(0x1111, 3, dest);
        assert!(
            sock.parse_response_v6(&foreign_te, &received, 3, dest, now)
                .is_none()
        );

        // Matching id/seq but a different embedded destination: collision
        // with another flow — must not be attributed to this probe.
        let other_dst = Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111);
        let wrong_dst_te = build_te(0x4242, 3, other_dst);
        assert!(
            sock.parse_response_v6(&wrong_dst_te, &received, 3, dest, now)
                .is_none()
        );
    }
}
