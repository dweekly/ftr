//! Spike: IPv6 traceroute mechanics — hop-limited probes and Time Exceeded.
//!
//! THE make-or-break question for unprivileged IPv6 traceroute on macOS:
//! can a `Domain::IPV6`/`Type::DGRAM`/`Protocol::ICMPV6` socket receive
//! ICMPv6 Time Exceeded (type 3) messages from intermediate routers, or
//! only Echo Replies? (On Linux IPv4 DGRAM sockets, errors arrive via
//! `IP_RECVERR`/errqueue, not the normal receive path.)
//!
//! Empirically answers, on the machine it runs on (primary target: macOS):
//!
//! 1. Send an Echo Request with `IPV6_UNICAST_HOPS` = 3 toward a distant
//!    host — does the Time Exceeded from the hop-3 router arrive on the
//!    DGRAM socket's normal receive path?
//! 2. Parse the Time Exceeded payload (invoking IPv6 header, 40 bytes, +
//!    invoking ICMPv6 Echo header, 8 bytes) and validate the embedded
//!    identifier/sequence match what we sent — required for demux since
//!    spike_icmpv6_socket showed the kernel delivers everything to
//!    every ICMPv6 DGRAM socket.
//! 3. `IPV6_RECVHOPLIMIT` + `recvmsg` cmsg: can we read the hop limit of
//!    the reply packet (needed for remaining-distance heuristics)?
//! 4. `ICMP6_FILTER`: socket2 has no API for it
//!    (<https://github.com/rust-lang/socket2/issues/199>), so set it via
//!    raw `setsockopt`. Verify semantics: BSD bit=1 means PASS
//!    (macOS SDK netinet/icmp6.h `ICMP6_FILTER_SETPASS`). Prove the filter
//!    works by first blocking Time Exceeded (probe gets no answer), then
//!    passing it (probe gets the Time Exceeded).
//!
//! If the DGRAM socket cannot see Time Exceeded, re-run as root to test
//! whether a RAW ICMPv6 socket can (the spike auto-detects euid 0).
//!
//! Run: `cargo run --example spike_traceroute6`
//!
//! Findings are recorded in docs/IPV6_DESIGN.md. This spike stays in-repo as
//! a permanent diagnostic: re-run it if kernel/OS behavior is in question.

/// ICMPv6 message types (RFC 4443).
const ICMPV6_DEST_UNREACHABLE: u8 = 1;
/// Time Exceeded (RFC 4443 section 3.3).
const ICMPV6_TIME_EXCEEDED: u8 = 3;
/// Echo Request (RFC 4443 section 4.1).
const ICMPV6_ECHO_REQUEST: u8 = 128;
/// Echo Reply (RFC 4443 section 4.2).
const ICMPV6_ECHO_REPLY: u8 = 129;

/// Hop limit for the TTL-limited probe: small enough that we hit an
/// intermediate router well before reaching Google's anycast edge (which is
/// typically 6+ hops away), large enough to get past the local LAN.
const PROBE_HOP_LIMIT: u32 = 3;

/// How long to wait for each reply (generous; a hop-3 router is < 20 ms away
/// on this network).
const RECV_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

#[cfg(any(target_os = "macos", target_os = "linux", target_os = "freebsd"))]
mod spike {
    use super::{
        ICMPV6_DEST_UNREACHABLE, ICMPV6_ECHO_REPLY, ICMPV6_ECHO_REQUEST, ICMPV6_TIME_EXCEEDED,
        PROBE_HOP_LIMIT, RECV_TIMEOUT,
    };
    use socket2::{Domain, Protocol, SockAddr, Socket, Type};
    use std::net::{Ipv6Addr, SocketAddrV6};
    use std::os::fd::AsRawFd;

    /// Google Public DNS IPv6 anycast — a distant echo responder so a
    /// hop-limit-3 probe expires at an intermediate router.
    const TARGET: Ipv6Addr = Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888);

    /// `ICMP6_FILTER` socket option, `IPPROTO_ICMPV6` level. Not exposed by
    /// the libc crate for Apple targets; value verified against macOS SDK
    /// header netinet6/in6.h line 392: `#define ICMP6_FILTER 18`.
    #[cfg(target_os = "macos")]
    const ICMP6_FILTER: libc::c_int = 18;
    /// On FreeBSD the value is also 18 (netinet6/in6.h) but this spike has
    /// only been verified on macOS; on Linux the option value is 1 and the
    /// bit semantics are INVERTED (bit=1 means block) — not validated here.
    #[cfg(not(target_os = "macos"))]
    const ICMP6_FILTER: libc::c_int = -1; // sentinel: filter test skipped

    /// Mirror of `struct icmp6_filter` (macOS SDK netinet/icmp6.h line 624):
    /// 256 bits, one per ICMPv6 type. BSD semantics: bit SET means PASS
    /// (`ICMP6_FILTER_SETPASS` ORs the bit in; `SETBLOCKALL` is memset 0).
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
        /// `ICMP6_FILTER_SETPASS` macro:
        /// `filt[type >> 5] |= 1 << (type & 31)`.
        fn pass(mut self, ty: u8) -> Self {
            self.icmp6_filt[(ty >> 5) as usize] |= 1u32 << (ty & 31);
            self
        }
    }

    /// Apply an ICMP6_FILTER to a socket via raw setsockopt (no socket2 API;
    /// see rust-lang/socket2#199).
    fn set_icmp6_filter(socket: &Socket, filter: &Icmp6Filter) -> std::io::Result<()> {
        // SAFETY: fd is valid for the lifetime of `socket`; the buffer is a
        // properly sized repr(C) mirror of struct icmp6_filter.
        let rc = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_ICMPV6,
                ICMP6_FILTER,
                (filter as *const Icmp6Filter).cast(),
                std::mem::size_of::<Icmp6Filter>() as libc::socklen_t,
            )
        };
        if rc == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }

    /// Build an ICMPv6 Echo Request (checksum zeroed; spike_icmpv6_socket
    /// proved the kernel fills it in on both DGRAM and RAW ICMPv6 sockets).
    fn build_echo_request(identifier: u16, sequence: u16) -> Vec<u8> {
        let mut pkt = vec![ICMPV6_ECHO_REQUEST, 0, 0, 0];
        pkt.extend_from_slice(&identifier.to_be_bytes());
        pkt.extend_from_slice(&sequence.to_be_bytes());
        pkt.extend_from_slice(b"ftr-ipv6-spike-tr");
        pkt
    }

    /// One received ICMPv6 packet plus recvmsg metadata.
    struct Received {
        bytes: Vec<u8>,
        from: Option<Ipv6Addr>,
        /// Hop limit of the received packet, from the IPV6_HOPLIMIT cmsg
        /// (present only if IPV6_RECVHOPLIMIT was enabled).
        hop_limit: Option<u32>,
    }

    /// Receive one datagram with libc::recvmsg so we can read ancillary
    /// data (socket2 0.6 exposes recvmsg but no cmsg parser). Honors the
    /// socket's SO_RCVTIMEO. Returns None on timeout.
    fn recvmsg_one(socket: &Socket) -> Option<Received> {
        let mut buf = [0u8; 1500];
        let mut name: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
        // Space for a few cmsgs; CMSG_SPACE(4) is ~16 bytes on Darwin, 256
        // is comfortably enough.
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
            return None; // timeout (EAGAIN) or error
        }

        let mut hop_limit = None;
        // SAFETY: cmsg iteration follows the CMSG_* contract on the msghdr
        // that recvmsg just filled in.
        unsafe {
            let mut cmsg = libc::CMSG_FIRSTHDR(&raw const msg);
            while !cmsg.is_null() {
                if (*cmsg).cmsg_level == libc::IPPROTO_IPV6
                    && (*cmsg).cmsg_type == libc::IPV6_HOPLIMIT
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

        let from = if msg.msg_namelen as usize >= std::mem::size_of::<libc::sockaddr_in6>() {
            Some(Ipv6Addr::from(name.sin6_addr.s6_addr))
        } else {
            None
        };
        Some(Received {
            bytes: buf[..n as usize].to_vec(),
            from,
            hop_limit,
        })
    }

    /// Parse and print a Time Exceeded message; returns the embedded
    /// (identifier, sequence) if the invoking packet was an ICMPv6 Echo.
    ///
    /// Layout (RFC 4443 section 3.3): 8-byte ICMPv6 header (type, code,
    /// checksum, 4 unused) followed by as much of the invoking packet as
    /// fits — for our probes that is the invoking IPv6 header (40 bytes,
    /// RFC 8200 section 3) then the invoking ICMPv6 Echo header (8 bytes).
    fn parse_time_exceeded(bytes: &[u8]) -> Option<(u16, u16)> {
        if bytes.len() < 8 + 40 + 8 {
            println!(
                "      too short for TE + invoking IPv6 + ICMPv6: {}",
                bytes.len()
            );
            return None;
        }
        let inner_ip = &bytes[8..48];
        let version = inner_ip[0] >> 4;
        let next_header = inner_ip[6];
        let inner_hop_limit = inner_ip[7];
        let src = Ipv6Addr::from(<[u8; 16]>::try_from(&inner_ip[8..24]).ok()?);
        let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&inner_ip[24..40]).ok()?);
        println!(
            "      embedded IPv6: version={version} next_header={next_header} \
             hop_limit={inner_hop_limit} src={src} dst={dst}"
        );
        if next_header != 58 {
            println!("      embedded packet is not ICMPv6 (next_header != 58)");
            return None;
        }
        let inner_icmp = &bytes[48..56];
        let id = u16::from_be_bytes([inner_icmp[4], inner_icmp[5]]);
        let seq = u16::from_be_bytes([inner_icmp[6], inner_icmp[7]]);
        println!(
            "      embedded ICMPv6: type={} code={} identifier=0x{id:04x} sequence={seq}",
            inner_icmp[0], inner_icmp[1]
        );
        Some((id, seq))
    }

    /// Send one hop-limited probe on `socket` and drain replies until we see
    /// a Time Exceeded matching (id, seq), an Echo Reply, or a timeout.
    /// Returns true if a matching Time Exceeded arrived.
    fn probe_and_wait(socket: &Socket, id: u16, seq: u16) -> bool {
        let dest = SockAddr::from(SocketAddrV6::new(TARGET, 0, 0, 0));
        if let Err(e) = socket.send_to(&build_echo_request(id, seq), &dest) {
            println!("    send failed: {e}");
            return false;
        }
        println!("    probe sent (hop_limit={PROBE_HOP_LIMIT}, id=0x{id:04x}, seq={seq})");
        // Drain: the socket sees ALL ICMPv6 traffic (spike_icmpv6_socket
        // finding), so skip unrelated packets until timeout.
        let deadline = std::time::Instant::now() + RECV_TIMEOUT;
        while std::time::Instant::now() < deadline {
            let Some(rcv) = recvmsg_one(socket) else {
                break; // timeout
            };
            let ty = rcv.bytes.first().copied().unwrap_or(0);
            match ty {
                ICMPV6_TIME_EXCEEDED => {
                    println!(
                        "    got TIME EXCEEDED from {:?} (reply hop_limit cmsg: {:?})",
                        rcv.from, rcv.hop_limit
                    );
                    if let Some((got_id, got_seq)) = parse_time_exceeded(&rcv.bytes) {
                        if got_id == id && got_seq == seq {
                            println!("      => embedded id/seq MATCH our probe");
                            return true;
                        }
                        println!("      => embedded id/seq do not match (someone else's probe)");
                    }
                }
                ICMPV6_ECHO_REPLY => {
                    println!(
                        "    got ECHO REPLY from {:?} — probe reached target?! \
                         (hop limit not honored)",
                        rcv.from
                    );
                }
                ICMPV6_DEST_UNREACHABLE => {
                    println!("    got DESTINATION UNREACHABLE from {:?}", rcv.from);
                }
                other => {
                    println!("    (skipping unrelated ICMPv6 type {other} — NDP/RA noise)");
                }
            }
        }
        false
    }

    /// Run the hop-limited probe test on one socket type.
    fn run_probe_test(label: &str, ty: Type, id: u16) -> bool {
        println!("\n[{label}] hop-limited probe on {ty:?} ICMPv6 socket:");
        let socket = match Socket::new(Domain::IPV6, ty, Some(Protocol::ICMPV6)) {
            Ok(s) => s,
            Err(e) => {
                println!(
                    "    cannot open socket: {e} (os error {:?})",
                    e.raw_os_error()
                );
                return false;
            }
        };
        socket
            .set_read_timeout(Some(RECV_TIMEOUT))
            .expect("set_read_timeout");
        socket
            .set_unicast_hops_v6(PROBE_HOP_LIMIT)
            .expect("set IPV6_UNICAST_HOPS");
        match socket.unicast_hops_v6() {
            Ok(v) => println!("    IPV6_UNICAST_HOPS readback: {v}"),
            Err(e) => println!("    IPV6_UNICAST_HOPS readback failed: {e}"),
        }
        socket
            .set_recv_hoplimit_v6(true)
            .expect("set IPV6_RECVHOPLIMIT");
        probe_and_wait(&socket, id, 1)
    }

    /// ICMP6_FILTER validation (macOS only — constant verified there).
    fn run_filter_test() {
        println!("\n[3] ICMP6_FILTER via raw setsockopt (socket2 has no API):");
        if ICMP6_FILTER < 0 {
            println!("    skipped: ICMP6_FILTER constant only verified for macOS");
            return;
        }
        // Phase A: pass ONLY Echo Reply; a hop-limited probe's Time
        // Exceeded must NOT be delivered. Absence proves the filter works.
        println!("    phase A: filter passes ONLY Echo Reply (129); expect NO Time Exceeded:");
        let sock = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::ICMPV6))
            .expect("filter test socket");
        sock.set_read_timeout(Some(RECV_TIMEOUT)).expect("timeout");
        sock.set_unicast_hops_v6(PROBE_HOP_LIMIT).expect("hops");
        sock.set_recv_hoplimit_v6(true).expect("recvhoplimit");
        let only_echo = Icmp6Filter::block_all().pass(ICMPV6_ECHO_REPLY);
        match set_icmp6_filter(&sock, &only_echo) {
            Ok(()) => println!("    setsockopt(ICMP6_FILTER) OK"),
            Err(e) => {
                println!("    setsockopt(ICMP6_FILTER) FAILED: {e}");
                return;
            }
        }
        let saw_te = probe_and_wait(&sock, 0x4444, 1);
        println!(
            "    => Time Exceeded delivered with it filtered out: {saw_te} \
             (false means the filter blocks as intended)"
        );

        // Phase B: same socket, now pass Time Exceeded (and friends);
        // the probe's Time Exceeded should arrive.
        println!("    phase B: filter passes 1/3/129; expect Time Exceeded again:");
        let tracer_filter = Icmp6Filter::block_all()
            .pass(ICMPV6_DEST_UNREACHABLE)
            .pass(ICMPV6_TIME_EXCEEDED)
            .pass(ICMPV6_ECHO_REPLY);
        match set_icmp6_filter(&sock, &tracer_filter) {
            Ok(()) => println!("    setsockopt(ICMP6_FILTER) OK"),
            Err(e) => {
                println!("    setsockopt(ICMP6_FILTER) FAILED: {e}");
                return;
            }
        }
        let saw_te = probe_and_wait(&sock, 0x4444, 2);
        println!("    => Time Exceeded delivered with filter passing type 3: {saw_te}");
    }

    pub fn run() {
        let euid = unsafe { libc::geteuid() };
        println!("=== spike_traceroute6: hop-limited ICMPv6 probes (euid={euid}) ===");

        // [1] THE question: Time Exceeded on unprivileged DGRAM.
        let dgram_ok = run_probe_test("1", Type::DGRAM, 0x3333);
        println!(
            "\n    VERDICT: DGRAM ICMPv6 socket {} receive Time Exceeded on macOS",
            if dgram_ok { "CAN" } else { "can NOT" }
        );

        // [2] RAW comparison — only possible as root.
        if euid == 0 {
            let raw_ok = run_probe_test("2", Type::RAW, 0x3355);
            println!(
                "\n    VERDICT: RAW ICMPv6 socket {} receive Time Exceeded",
                if raw_ok { "CAN" } else { "can NOT" }
            );
        } else {
            println!(
                "\n[2] RAW ICMPv6 comparison skipped (needs root). To test, run:\n    \
                 sudo cargo run --example spike_traceroute6"
            );
        }

        // [3] ICMP6_FILTER.
        run_filter_test();

        println!("\n=== spike_traceroute6 done ===");
    }
}

#[cfg(any(target_os = "macos", target_os = "linux", target_os = "freebsd"))]
fn main() {
    spike::run();
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "freebsd")))]
fn main() {
    println!("spike_traceroute6: only implemented for macOS/Linux/FreeBSD");
}
