//! BSD async raw ICMPv6 socket implementation
//!
//! IPv6 traceroute for FreeBSD, OpenBSD, NetBSD, and DragonFly BSD. Unlike
//! macOS (which shares the BSD network stack heritage but added unprivileged
//! DGRAM ICMP), the other BSDs have no unprivileged ICMP socket of either
//! family, so raw ICMPv6 — root required, exactly like the platforms' IPv4
//! mode in [`super::bsd`] — is the only option.
//!
//! Three raw-ICMPv6 behaviors this module relies on (all RFC 3542 semantics
//! from the shared KAME IPv6 stack, validated live on Darwin and Linux raw
//! sockets in `docs/IPV6_DESIGN.md`; the FreeBSD CI VM is the integration
//! gate for this cfg arm since no local BSD test environment was available):
//!
//! 1. **The kernel computes the ICMPv6 checksum on send.** RFC 3542
//!    section 3.1: "The kernel will calculate and insert the ICMPv6 checksum
//!    for ICMPv6 raw sockets, since this checksum is mandatory." — and an
//!    attempt to set `IPV6_CHECKSUM` on an ICMPv6 socket *fails* (same
//!    section). FreeBSD ip6(4) concurs: "The offset of the checksum for
//!    ICMPv6 sockets cannot be relocated or turned off." So the packet's
//!    checksum field stays zero and `IPV6_CHECKSUM` is never set.
//! 2. **Received buffers start at the ICMPv6 header.** The kernel never
//!    prepends the IPv6 header on ICMPv6 raw sockets (RFC 3542 section 2.6
//!    behavior, unlike IPv4 raw) — the [`super::icmpv6`] codec assumes this.
//! 3. **No kernel demux by echo identifier.** A raw ICMPv6 socket sees all
//!    inbound ICMPv6, so userspace identifier + sequence (+ embedded
//!    destination) matching is mandatory, on Echo Replies and on the probe
//!    embedded in Time Exceeded / Destination Unreachable errors.
//!
//! The reply's own hop limit is not read here: that needs `recvmsg` with the
//! `IPV6_HOPLIMIT` cmsg (as the macOS path does for verbose diagnostics),
//! while this module mirrors the plain `recv_from` receive loop of the
//! proven IPv4 [`super::bsd`] implementation. Nothing consumes the reply
//! hop limit on this path, so the simpler loop wins.

use crate::TimingConfig;
use crate::probe::{ProbeInfo, ProbeResponse};
use crate::socket::icmpv6;
use crate::socket::traits::{ProbeMode, ProbeSocket};
use crate::traceroute::TracerouteError;
use socket2::{Domain, Protocol, SockAddr, Socket as Socket2, Type};
use std::future::Future;
use std::net::{IpAddr, Ipv6Addr, SocketAddrV6};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::oneshot;

/// Receive buffer size — a full Ethernet-MTU packet comfortably fits,
/// matching the IPv4 BSD implementation's 1500-byte buffer.
const RECV_BUFFER_SIZE: usize = 1500;

/// Polling interval while waiting for a reply on the non-blocking socket,
/// matching the IPv4 BSD implementation's 1 ms poll loop.
const RECV_POLL_INTERVAL: Duration = Duration::from_millis(1);

/// `ICMP6_FILTER` socket option (level `IPPROTO_ICMPV6`). The libc crate
/// does not define it for the BSDs; the value 18 is verified against each
/// OS's `sys/netinet6/in6.h` (`#define ICMP6_FILTER 18`): FreeBSD
/// (freebsd-src main), OpenBSD (src master), NetBSD (src trunk), and
/// DragonFly (master) all agree — unsurprising, since all inherit the KAME
/// stack, as does Darwin (macOS uses the same 18; Linux differs, optname 1).
#[cfg(any(target_os = "freebsd", target_os = "openbsd"))]
const ICMP6_FILTER: libc::c_int = 18;

/// Mirror of `struct icmp6_filter` (FreeBSD/OpenBSD `netinet/icmp6.h`):
/// 256 bits, one per ICMPv6 type. BSD semantics: bit SET means PASS
/// (`ICMP6_FILTER_SETPASS` ORs the bit in; `SETBLOCKALL` is memset 0 —
/// verified against both OSes' headers). Linux inverts these semantics
/// (bit = block) — do not reuse as-is there.
#[cfg(any(target_os = "freebsd", target_os = "openbsd"))]
#[repr(C)]
struct Icmp6Filter {
    icmp6_filt: [u32; 8],
}

#[cfg(any(target_os = "freebsd", target_os = "openbsd"))]
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

/// Apply the traceroute `ICMP6_FILTER` (pass Destination Unreachable, Time
/// Exceeded, Echo Reply only) via raw setsockopt — socket2 exposes no API
/// for it (<https://github.com/rust-lang/socket2/issues/199>).
///
/// Best-effort kernel-side noise shedding only: userspace identifier
/// filtering in [`BsdAsyncIcmpV6Socket::parse_raw_response`] is what
/// guarantees correctness, so a setsockopt failure is silently ignored.
/// NetBSD/DragonFly skip this entirely (ftr carries no libc dependency
/// there) and rely on the userspace filter alone.
#[cfg(any(target_os = "freebsd", target_os = "openbsd"))]
fn apply_icmp6_filter(socket: &Socket2) {
    use std::os::fd::AsRawFd;

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
    // Failure intentionally ignored — optimization only, see above.
    let _ = rc;
}

#[cfg(not(any(target_os = "freebsd", target_os = "openbsd")))]
fn apply_icmp6_filter(_socket: &Socket2) {}

/// BSD async raw ICMPv6 socket implementation.
///
/// Mirrors the per-probe-socket design of the IPv4 [`super::bsd`]
/// implementation: each probe opens a fresh raw socket, sets
/// `IPV6_UNICAST_HOPS`, sends one hop-limited echo, and polls for a
/// matching response until the socket read timeout.
pub struct BsdAsyncIcmpV6Socket {
    icmp_identifier: u16,
    destination_reached: Arc<AtomicBool>,
    pending_count: Arc<AtomicUsize>,
    timing_config: TimingConfig,
}

impl BsdAsyncIcmpV6Socket {
    /// Create a new BSD async raw ICMPv6 socket handle.
    ///
    /// Probes raw-socket availability up front so the root requirement
    /// surfaces as a typed [`TracerouteError::InsufficientPermissions`] at
    /// setup time, not on the first probe.
    pub fn new_with_config(timing_config: TimingConfig) -> Result<Self, TracerouteError> {
        Socket2::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6)).map_err(|e| {
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                TracerouteError::InsufficientPermissions {
                    required: "root".to_string(),
                    suggestion:
                        "Run with sudo, or make the binary setuid root (chown root:wheel ftr && chmod u+s ftr)"
                            .to_string(),
                }
            } else {
                TracerouteError::SocketError(format!("Failed to create raw ICMPv6 socket: {e}"))
            }
        })?;

        Ok(BsdAsyncIcmpV6Socket {
            // Same per-process identifier scheme as the IPv4 BSD mode.
            icmp_identifier: std::process::id() as u16,
            destination_reached: Arc::new(AtomicBool::new(false)),
            pending_count: Arc::new(AtomicUsize::new(0)),
            timing_config,
        })
    }

    /// Parse one received ICMPv6 packet (buffer starts AT the ICMPv6
    /// header) against this probe's id/seq. Returns `(from, is_destination)`
    /// or `None` for foreign/noise packets, which are silently skipped —
    /// the raw socket sees all inbound ICMPv6.
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
                // collisions with other flows (same contract as the macOS
                // and Linux v6 implementations).
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

impl ProbeSocket for BsdAsyncIcmpV6Socket {
    fn mode(&self) -> ProbeMode {
        ProbeMode::RawIcmp
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

            // Socket setup + send, with the pending count kept honest on
            // any early error.
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
                apply_icmp6_filter(&socket);

                // Same payload tag as the IPv4 BSD probe packets.
                let mut payload = [0u8; 16];
                let tag = b"ftr-traceroute";
                payload[..tag.len()].copy_from_slice(tag);
                // Checksum stays zero: the kernel computes it on raw ICMPv6
                // sockets (RFC 3542 section 3.1 / FreeBSD ip6(4) — module docs).
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
            let timeout = self.timing_config.socket_read_timeout;

            let (tx, rx) = oneshot::channel();

            tokio::spawn(async move {
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
                                    BsdAsyncIcmpV6Socket::parse_raw_response(
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
                                // Not ours — keep draining without sleeping.
                                continue;
                            }
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                        Err(_) => {
                            pending_count.fetch_sub(1, Ordering::Relaxed);
                            break;
                        }
                    }

                    if sent_at.elapsed() >= timeout {
                        pending_count.fetch_sub(1, Ordering::Relaxed);
                        let _ = tx.send(ProbeResponse {
                            from_addr: dest,
                            sequence,
                            ttl,
                            rtt: timeout,
                            received_at: Instant::now(),
                            is_destination: false,
                            is_timeout: true,
                        });
                        break;
                    }

                    tokio::time::sleep(RECV_POLL_INTERVAL).await;
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

    const GOOGLE_V6: Ipv6Addr = Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888);
    const HOP_ROUTER: Ipv6Addr = Ipv6Addr::new(0x2001, 0x5a8, 0x657, 0x21, 0, 0, 0xf0, 4);

    /// Synthesize the Time Exceeded a router would send for one of our
    /// probes (layout matches the live capture in docs/IPV6_DESIGN.md).
    fn build_te(id: u16, seq: u16, embedded_dst: Ipv6Addr) -> Vec<u8> {
        let mut buf = vec![0u8; 56];
        buf[0] = icmpv6::ICMPV6_TIME_EXCEEDED;
        buf[8] = 6 << 4; // embedded IPv6 version
        buf[14] = icmpv6::IPV6_NEXT_HEADER_ICMPV6; // embedded next header
        buf[32..48].copy_from_slice(&embedded_dst.octets());
        buf[48] = icmpv6::ICMPV6_ECHO_REQUEST;
        buf[52..54].copy_from_slice(&id.to_be_bytes());
        buf[54..56].copy_from_slice(&seq.to_be_bytes());
        buf
    }

    #[test]
    fn test_parse_raw_response_echo_reply_demux() {
        let id = 0x4242;
        let seq = 7;

        // Own echo reply matches and is the destination.
        let mut own = icmpv6::build_echo_request_v6(id, seq, &[]);
        own[0] = icmpv6::ICMPV6_ECHO_REPLY;
        assert_eq!(
            BsdAsyncIcmpV6Socket::parse_raw_response(id, &own, GOOGLE_V6, seq, GOOGLE_V6),
            Some((GOOGLE_V6, true))
        );

        // Foreign identifier: another process's reply, skipped.
        let mut foreign = icmpv6::build_echo_request_v6(0x9999, seq, &[]);
        foreign[0] = icmpv6::ICMPV6_ECHO_REPLY;
        assert_eq!(
            BsdAsyncIcmpV6Socket::parse_raw_response(id, &foreign, GOOGLE_V6, seq, GOOGLE_V6),
            None
        );

        // Own identifier, wrong sequence (another probe of this trace): skipped.
        let mut wrong_seq = icmpv6::build_echo_request_v6(id, seq + 1, &[]);
        wrong_seq[0] = icmpv6::ICMPV6_ECHO_REPLY;
        assert_eq!(
            BsdAsyncIcmpV6Socket::parse_raw_response(id, &wrong_seq, GOOGLE_V6, seq, GOOGLE_V6),
            None
        );
    }

    #[test]
    fn test_parse_raw_response_time_exceeded_demux() {
        let id = 0x4242;
        let seq = 3;

        // Matching TE from an intermediate router.
        let te = build_te(id, seq, GOOGLE_V6);
        assert_eq!(
            BsdAsyncIcmpV6Socket::parse_raw_response(id, &te, HOP_ROUTER, seq, GOOGLE_V6),
            Some((HOP_ROUTER, false))
        );

        // Foreign embedded identifier: someone else's expired probe.
        let foreign = build_te(0x1111, seq, GOOGLE_V6);
        assert_eq!(
            BsdAsyncIcmpV6Socket::parse_raw_response(id, &foreign, HOP_ROUTER, seq, GOOGLE_V6),
            None
        );

        // Matching id/seq but a different embedded destination: collision
        // with another flow — must not be attributed to this probe.
        let other_dst = Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111);
        let wrong_dst = build_te(id, seq, other_dst);
        assert_eq!(
            BsdAsyncIcmpV6Socket::parse_raw_response(id, &wrong_dst, HOP_ROUTER, seq, GOOGLE_V6),
            None
        );
    }

    #[test]
    fn test_parse_raw_response_skips_ndp_noise() {
        // Router Advertisement bytes as observed live on a Darwin DGRAM
        // socket (docs/IPV6_DESIGN.md) — raw BSD sockets see the same
        // chatter when ICMP6_FILTER is unavailable or unset.
        let ra = [134u8, 0, 0, 0, 0x40, 0xc8, 0x07, 0x08];
        assert_eq!(
            BsdAsyncIcmpV6Socket::parse_raw_response(1, &ra, HOP_ROUTER, 1, GOOGLE_V6),
            None
        );
    }

    #[cfg(any(target_os = "freebsd", target_os = "openbsd"))]
    #[test]
    fn test_icmp6_filter_pass_bits() {
        // Mirror ICMP6_FILTER_SETPASS semantics for the three types the
        // traceroute filter passes (bit set = PASS on the BSDs).
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

    #[test]
    fn test_socket_initialization_permission_behavior() {
        // As root the handle must build; without root the typed
        // InsufficientPermissions error must surface (raw sockets are the
        // only ICMPv6 mode on the BSDs).
        let result = BsdAsyncIcmpV6Socket::new_with_config(TimingConfig::default());
        if crate::socket::utils::is_root() {
            assert!(result.is_ok(), "root must be able to open raw ICMPv6");
        } else {
            assert!(
                matches!(result, Err(TracerouteError::InsufficientPermissions { .. })),
                "non-root must get the typed permission error"
            );
        }
    }
}
