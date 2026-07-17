//! Spike: Linux-specific ICMPv6 ping-socket and UDP6+`IPV6_RECVERR` behavior.
//!
//! Companion to `spike_icmpv6_socket`/`spike_traceroute6` (macOS-validated);
//! this one answers the Linux questions from docs/IPV6_DESIGN.md:
//!
//! 1. Are ICMPv6 ping sockets (`SOCK_DGRAM`/`IPPROTO_ICMPV6`, gated by
//!    `net.ipv4.ping_group_range` — yes, the *ipv4* sysctl gates v6 too)
//!    available unprivileged? Does the kernel REWRITE the echo identifier
//!    (it does for v4 ping sockets)? Does it demux replies per-socket by id
//!    (opposite of the Darwin finding, where every socket sees everything)?
//! 2. Do ICMPv6 Time Exceeded messages reach a ping socket's normal receive
//!    path, the error queue (`IPV6_RECVERR` + `MSG_ERRQUEUE`), or neither?
//! 3. `ICMP6_FILTER` on Linux: optname is 1 (not 18 as on Darwin) and the
//!    bit semantics are INVERTED vs BSD (glibc `ICMP6_FILTER_SETPASSALL` is
//!    `memset 0`, `SETBLOCKALL` is `memset 0xFF`, so bit SET = BLOCK) — does
//!    it work on ping sockets at all, and with those semantics?
//! 4. Does unprivileged UDP6 + `IPV6_RECVERR` traceroute work like ftr's v4
//!    Linux UDP mode (`src/socket/linux.rs`)? This needs no ping_group_range
//!    and no root, so it is the make-or-break for unprivileged Linux v6.
//! 5. Is the reply packet's hop limit readable — `IPV6_HOPLIMIT` cmsg on the
//!    normal path, and attached to `MSG_ERRQUEUE` messages too?
//!
//! Run: `cargo run --example spike_linux_v6`
//!
//! If `ping_group_range` excludes your gid (default `1 0` disables ping
//! sockets for everyone), the ping-socket sections report EACCES and are
//! skipped; the UDP sections still run. To exercise the ping-socket sections
//! without changing host config, run inside a container whose network
//! namespace has the sysctl widened (the sysctl is per-netns):
//!
//! ```text
//! docker network create --ipv6 ftr6
//! docker run --rm --network ftr6 --user 1000:1000 \
//!   --sysctl net.ipv4.ping_group_range="0 2147483647" \
//!   -v $PWD/target/debug/examples:/spikes ubuntu:24.04 /spikes/spike_linux_v6
//! ```
//!
//! Findings are recorded in docs/IPV6_DESIGN.md. This spike stays in-repo as
//! a permanent diagnostic: re-run it if kernel behavior is in question.

#[cfg(target_os = "linux")]
mod spike {
    use socket2::{Domain, Protocol, SockAddr, Socket, Type};
    use std::net::{Ipv6Addr, SocketAddrV6};
    use std::os::fd::AsRawFd;
    use std::time::{Duration, Instant};

    /// Google Public DNS IPv6 anycast — a distant responder several hops out.
    const TARGET: Ipv6Addr = Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888);

    /// ICMPv6 Destination Unreachable (RFC 4443 section 3.1).
    const ICMPV6_DEST_UNREACH: u8 = 1;
    /// ICMPv6 Time Exceeded (RFC 4443 section 3.3).
    const ICMPV6_TIME_EXCEEDED: u8 = 3;
    /// ICMPv6 Echo Request (RFC 4443 section 4.1).
    const ICMPV6_ECHO_REQUEST: u8 = 128;
    /// ICMPv6 Echo Reply (RFC 4443 section 4.2).
    const ICMPV6_ECHO_REPLY: u8 = 129;

    /// Destination Unreachable code 4 = port unreachable — what the final
    /// destination answers to a UDP probe (RFC 4443 section 3.1).
    const ICMPV6_UNREACH_PORT: u8 = 4;

    /// `ICMPV6_FILTER` socket option at level `IPPROTO_ICMPV6`. Verified on
    /// Ubuntu 24.04: /usr/include/linux/icmpv6.h line 150
    /// (`#define ICMPV6_FILTER 1`) and glibc /usr/include/netinet/icmp6.h
    /// line 26 (`#define ICMP6_FILTER 1`). Darwin uses 18 instead.
    const ICMPV6_FILTER: libc::c_int = 1;

    /// `IPV6_RECVERR` socket option at level `IPPROTO_IPV6`. Verified:
    /// /usr/include/linux/in6.h line 178 (`#define IPV6_RECVERR 25`).
    const IPV6_RECVERR: libc::c_int = 25;

    /// `sock_extended_err.ee_origin` value for errors that arrived as ICMPv6:
    /// /usr/include/linux/errqueue.h line 31 (`#define SO_EE_ORIGIN_ICMP6 3`).
    const SO_EE_ORIGIN_ICMP6: u8 = 3;

    /// Hop limit for TTL-limited probes: past the LAN, well short of Google.
    const PROBE_HOP_LIMIT: u32 = 3;

    /// Per-wait receive deadline. Hop routers answer in tens of ms; 3 s keeps
    /// negative results ("nothing arrived") convincing without stalling.
    const RECV_TIMEOUT: Duration = Duration::from_secs(3);

    /// Max hops for the UDP traceroute scan (Google DNS is ~6-10 hops from
    /// typical eyeball networks; 16 leaves margin without a long tail).
    const UDP_MAX_HOPS: u32 = 16;

    /// Classic traceroute UDP destination port base (same convention as
    /// ftr's v4 UDP mode in src/socket/linux.rs).
    const UDP_BASE_PORT: u16 = 33434;

    /// Mirror of Linux `struct sock_extended_err`
    /// (/usr/include/linux/errqueue.h line 15), same shape as the one in
    /// src/socket/linux.rs.
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

    /// Mirror of `struct icmp6_filter` (glibc netinet/icmp6.h): 256 bits,
    /// one per ICMPv6 type. LINUX semantics (inverted vs BSD): bit SET =
    /// BLOCK. `ICMP6_FILTER_SETPASSALL` = memset 0, `SETBLOCKALL` = memset
    /// 0xFF, `SETBLOCK` ORs the bit in, `SETPASS` clears it
    /// (/usr/include/netinet/icmp6.h lines 89-105 on Ubuntu 24.04).
    #[repr(C)]
    struct Icmp6Filter {
        icmp6_filt: [u32; 8],
    }

    impl Icmp6Filter {
        /// `ICMP6_FILTER_SETBLOCKALL`: all bits set = block everything.
        fn block_all() -> Self {
            Icmp6Filter {
                icmp6_filt: [u32::MAX; 8],
            }
        }
        /// `ICMP6_FILTER_SETPASSALL`: all bits clear = pass everything.
        fn pass_all() -> Self {
            Icmp6Filter { icmp6_filt: [0; 8] }
        }
        /// `ICMP6_FILTER_SETPASS`: clear the bit for one type.
        fn pass(mut self, ty: u8) -> Self {
            self.icmp6_filt[(ty >> 5) as usize] &= !(1u32 << (ty & 31));
            self
        }
        /// `ICMP6_FILTER_SETBLOCK`: set the bit for one type.
        fn block(mut self, ty: u8) -> Self {
            self.icmp6_filt[(ty >> 5) as usize] |= 1u32 << (ty & 31);
            self
        }
    }

    /// Build an ICMPv6 Echo Request. Checksum left zero: ping sockets, like
    /// Darwin DGRAM ICMPv6, have the kernel compute it (v6 checksums need
    /// the pseudo-header, which userspace can't know before source
    /// selection).
    fn build_echo_request(identifier: u16, sequence: u16) -> Vec<u8> {
        let mut pkt = vec![ICMPV6_ECHO_REQUEST, 0, 0, 0];
        pkt.extend_from_slice(&identifier.to_be_bytes());
        pkt.extend_from_slice(&sequence.to_be_bytes());
        pkt.extend_from_slice(b"ftr-linux-v6-spike");
        pkt
    }

    /// One received message plus its recvmsg metadata.
    struct Received {
        bytes: Vec<u8>,
        from: Option<Ipv6Addr>,
        /// From the `IPV6_HOPLIMIT` cmsg, if `IPV6_RECVHOPLIMIT` was on.
        hop_limit: Option<u32>,
        /// From the `IPV6_RECVERR` cmsg (errqueue reads): the extended error
        /// plus the offender address that generated the ICMPv6 error.
        ext_err: Option<(SockExtendedErr, Option<Ipv6Addr>)>,
    }

    /// recvmsg with cmsg parsing (socket2 0.6 has no cmsg parser). Pass
    /// `libc::MSG_ERRQUEUE | libc::MSG_DONTWAIT` to poll the error queue.
    /// Returns None on EAGAIN/timeout.
    fn recvmsg_one(socket: &Socket, flags: libc::c_int) -> Option<Received> {
        let mut buf = [0u8; 1500];
        let mut name: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
        let mut control = [0u8; 512];
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
        let n = unsafe { libc::recvmsg(socket.as_raw_fd(), &raw mut msg, flags) };
        if n < 0 {
            return None; // EAGAIN (timeout / empty errqueue) or error
        }

        let mut hop_limit = None;
        let mut ext_err = None;
        // SAFETY: cmsg iteration follows the CMSG_* contract on the msghdr
        // that recvmsg just filled in.
        unsafe {
            let mut cmsg = libc::CMSG_FIRSTHDR(&raw const msg);
            while !cmsg.is_null() {
                let level = (*cmsg).cmsg_level;
                let ty = (*cmsg).cmsg_type;
                if level == libc::IPPROTO_IPV6 && ty == libc::IPV6_HOPLIMIT {
                    let mut v: libc::c_int = 0;
                    std::ptr::copy_nonoverlapping(
                        libc::CMSG_DATA(cmsg),
                        (&raw mut v).cast::<u8>(),
                        std::mem::size_of::<libc::c_int>(),
                    );
                    hop_limit = Some(v as u32);
                } else if level == libc::IPPROTO_IPV6 && ty == IPV6_RECVERR {
                    // SAFETY: for an IPV6_RECVERR cmsg the payload is a
                    // sock_extended_err optionally followed by the offender
                    // sockaddr (SO_EE_OFFENDER, linux/errqueue.h line 37).
                    let err_ptr = libc::CMSG_DATA(cmsg) as *const SockExtendedErr;
                    let ee = std::ptr::read_unaligned(err_ptr);
                    let addr_ptr =
                        (err_ptr as *const u8).add(std::mem::size_of::<SockExtendedErr>());
                    let sa6 = std::ptr::read_unaligned(addr_ptr as *const libc::sockaddr_in6);
                    let offender = if sa6.sin6_family == libc::AF_INET6 as libc::sa_family_t {
                        Some(Ipv6Addr::from(sa6.sin6_addr.s6_addr))
                    } else {
                        None
                    };
                    ext_err = Some((ee, offender));
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
            ext_err,
        })
    }

    /// Poll the error queue until a message or the deadline. The errqueue
    /// never blocks, so poll MSG_DONTWAIT on a short interval.
    fn wait_errqueue(socket: &Socket, deadline: Instant) -> Option<Received> {
        loop {
            if let Some(r) = recvmsg_one(socket, libc::MSG_ERRQUEUE | libc::MSG_DONTWAIT) {
                return Some(r);
            }
            if Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// The kernel-assigned local "port" of a ping socket is its ICMP echo
    /// identifier — read it back via getsockname.
    fn local_ident(socket: &Socket) -> Option<u16> {
        socket
            .local_addr()
            .ok()?
            .as_socket_ipv6()
            .map(|sa| sa.port())
    }

    /// Open an unprivileged ICMPv6 ping socket, or report exactly why not.
    fn open_ping_socket() -> Option<Socket> {
        match Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::ICMPV6)) {
            Ok(s) => {
                s.set_read_timeout(Some(RECV_TIMEOUT)).expect("timeout");
                Some(s)
            }
            Err(e) => {
                println!(
                    "    Socket::new(IPV6, DGRAM, ICMPV6) FAILED: {e} (os error {:?})",
                    e.raw_os_error()
                );
                None
            }
        }
    }

    fn ping_group_range() -> String {
        std::fs::read_to_string("/proc/sys/net/ipv4/ping_group_range")
            .map(|s| s.trim().replace('\t', " "))
            .unwrap_or_else(|e| format!("<unreadable: {e}>"))
    }

    /// [1]+[2] Identifier rewrite: send an echo with a lie for an id; see
    /// what getsockname and the reply say.
    fn run_ident_rewrite_test() -> bool {
        println!("\n[2] echo identifier rewrite on ping socket:");
        let Some(sock) = open_ping_socket() else {
            return false;
        };
        let dest = SockAddr::from(SocketAddrV6::new(TARGET, 0, 0, 0));
        let claimed_id = 0x1234u16;
        if let Err(e) = sock.send_to(&build_echo_request(claimed_id, 1), &dest) {
            println!("    send failed: {e}");
            return false;
        }
        let kernel_id = local_ident(&sock);
        println!("    sent echo claiming id=0x{claimed_id:04x} seq=1");
        println!(
            "    getsockname port (= kernel-assigned icmp ident): {:?}",
            kernel_id.map(|v| format!("0x{v:04x}"))
        );
        sock.set_recv_hoplimit_v6(true).expect("recvhoplimit");
        match recvmsg_one(&sock, 0) {
            Some(r) if r.bytes.len() >= 8 => {
                let ty = r.bytes[0];
                let id = u16::from_be_bytes([r.bytes[4], r.bytes[5]]);
                let seq = u16::from_be_bytes([r.bytes[6], r.bytes[7]]);
                println!(
                    "    received {} bytes from {:?}: type={ty} id=0x{id:04x} seq={seq} \
                     (reply hoplimit cmsg: {:?})",
                    r.bytes.len(),
                    r.from,
                    r.hop_limit
                );
                println!(
                    "    first byte = {ty} — {}",
                    if ty == ICMPV6_ECHO_REPLY {
                        "buffer starts at ICMPv6 header (no IPv6 header prepended)"
                    } else {
                        "UNEXPECTED leading byte"
                    }
                );
                let rewritten = Some(id) == kernel_id && id != claimed_id;
                println!(
                    "    => kernel {} the identifier (we sent 0x{claimed_id:04x}, \
                     reply carries 0x{id:04x})",
                    if rewritten {
                        "REWROTE"
                    } else if id == claimed_id {
                        "did NOT rewrite"
                    } else {
                        "did something unexpected with"
                    }
                );
                true
            }
            _ => {
                println!("    no reply within {RECV_TIMEOUT:?}");
                false
            }
        }
    }

    /// [3] Demux: two ping sockets probe concurrently with distinct seq
    /// markers; does each see only its own reply (per-socket demux by
    /// ident), or everything (Darwin behavior)?
    fn run_demux_test() {
        println!("\n[3] demux test: two ping sockets, distinct seq markers:");
        let (Some(sock_a), Some(sock_b)) = (open_ping_socket(), open_ping_socket()) else {
            return;
        };
        let dest = SockAddr::from(SocketAddrV6::new(TARGET, 0, 0, 0));
        sock_a
            .send_to(&build_echo_request(0, 41), &dest)
            .expect("send A");
        sock_b
            .send_to(&build_echo_request(0, 42), &dest)
            .expect("send B");
        println!(
            "    socket A ident={:?} sent seq=41; socket B ident={:?} sent seq=42",
            local_ident(&sock_a).map(|v| format!("0x{v:04x}")),
            local_ident(&sock_b).map(|v| format!("0x{v:04x}"))
        );
        for (label, sock, own_seq, other_seq) in
            [("A", &sock_a, 41u16, 42u16), ("B", &sock_b, 42, 41)]
        {
            let mut saw_own = false;
            let mut saw_other = false;
            let deadline = Instant::now() + RECV_TIMEOUT;
            sock.set_read_timeout(Some(Duration::from_millis(500)))
                .expect("timeout");
            while Instant::now() < deadline && !(saw_own && saw_other) {
                let Some(r) = recvmsg_one(sock, 0) else { break };
                if r.bytes.len() >= 8 && r.bytes[0] == ICMPV6_ECHO_REPLY {
                    let id = u16::from_be_bytes([r.bytes[4], r.bytes[5]]);
                    let seq = u16::from_be_bytes([r.bytes[6], r.bytes[7]]);
                    println!("    socket {label}: got reply id=0x{id:04x} seq={seq}");
                    saw_own |= seq == own_seq;
                    saw_other |= seq == other_seq;
                }
            }
            println!("    socket {label}: own reply: {saw_own}, foreign reply: {saw_other}");
        }
        println!(
            "    => foreign=false on both means the kernel demuxes per-socket by ident \
             (opposite of Darwin, which floods every DGRAM ICMPv6 socket)"
        );
    }

    /// [4] Where does Time Exceeded arrive on a ping socket: normal receive
    /// path, error queue, or nowhere?
    fn run_ping_time_exceeded_test() {
        println!("\n[4] Time Exceeded delivery to ping socket (hop_limit={PROBE_HOP_LIMIT}):");
        println!("    phase A: plain ping socket, NO IPV6_RECVERR:");
        if let Some(sock) = open_ping_socket() {
            sock.set_unicast_hops_v6(PROBE_HOP_LIMIT).expect("hops");
            let dest = SockAddr::from(SocketAddrV6::new(TARGET, 0, 0, 0));
            sock.send_to(&build_echo_request(0, 7), &dest)
                .expect("send");
            match recvmsg_one(&sock, 0) {
                Some(r) => println!(
                    "    normal path delivered type={} from {:?} ({} bytes)",
                    r.bytes.first().copied().unwrap_or(0),
                    r.from,
                    r.bytes.len()
                ),
                None => println!("    normal path: NOTHING within {RECV_TIMEOUT:?}"),
            }
            match wait_errqueue(&sock, Instant::now()) {
                Some(r) => println!(
                    "    errqueue (RECVERR off) unexpectedly had: ext_err={:?}",
                    r.ext_err
                ),
                None => println!("    errqueue (RECVERR off): empty, as expected"),
            }
        }

        println!("    phase B: ping socket WITH IPV6_RECVERR + IPV6_RECVHOPLIMIT:");
        let Some(sock) = open_ping_socket() else {
            return;
        };
        sock.set_unicast_hops_v6(PROBE_HOP_LIMIT).expect("hops");
        sock.set_recv_hoplimit_v6(true).expect("recvhoplimit");
        set_recverr(&sock).expect("IPV6_RECVERR");
        let dest = SockAddr::from(SocketAddrV6::new(TARGET, 0, 0, 0));
        sock.send_to(&build_echo_request(0, 8), &dest)
            .expect("send");
        let deadline = Instant::now() + RECV_TIMEOUT;
        match wait_errqueue(&sock, deadline) {
            Some(r) => {
                if let Some((ee, offender)) = r.ext_err {
                    println!(
                        "    errqueue: ee_errno={} ({}) ee_origin={} ee_type={} ee_code={} \
                         offender={offender:?} hoplimit_cmsg={:?}",
                        ee.ee_errno,
                        std::io::Error::from_raw_os_error(ee.ee_errno as i32),
                        ee.ee_origin,
                        ee.ee_type,
                        ee.ee_code,
                        r.hop_limit
                    );
                    println!(
                        "    => Time Exceeded {} the error queue (origin_icmp6={})",
                        if ee.ee_type == ICMPV6_TIME_EXCEEDED {
                            "ARRIVES on"
                        } else {
                            "did not match on"
                        },
                        ee.ee_origin == SO_EE_ORIGIN_ICMP6
                    );
                } else {
                    println!("    errqueue message without IPV6_RECVERR cmsg?!");
                }
            }
            None => println!("    errqueue: NOTHING within {RECV_TIMEOUT:?}"),
        }
        // And confirm the normal path stayed silent even with RECVERR on.
        sock.set_read_timeout(Some(Duration::from_millis(300)))
            .expect("timeout");
        match recvmsg_one(&sock, 0) {
            Some(r) => println!(
                "    normal path also delivered type={} from {:?}",
                r.bytes.first().copied().unwrap_or(0),
                r.from
            ),
            None => println!("    normal path: silent (error went only to the errqueue)"),
        }
    }

    /// [5] ICMP6_FILTER on a ping socket, Linux semantics (bit set = BLOCK).
    /// Positive control on echo replies: block 129 -> no reply; pass-all ->
    /// reply. Same probe both phases, so the filter is the only variable.
    fn run_filter_test() {
        println!("\n[5] ICMP6_FILTER (optname {ICMPV6_FILTER}, Linux bit=BLOCK semantics):");
        let Some(sock) = open_ping_socket() else {
            return;
        };
        let dest = SockAddr::from(SocketAddrV6::new(TARGET, 0, 0, 0));

        println!("    phase A: filter BLOCKS Echo Reply (bit 129 set); expect NO reply:");
        let block_echo = Icmp6Filter::pass_all().block(ICMPV6_ECHO_REPLY);
        match set_icmp6_filter(&sock, &block_echo) {
            Ok(()) => println!("    setsockopt(ICMPV6_FILTER) OK"),
            Err(e) => {
                println!("    setsockopt(ICMPV6_FILTER) FAILED: {e} — filter unusable here");
                return;
            }
        }
        sock.send_to(&build_echo_request(0, 51), &dest)
            .expect("send");
        let got_a = recvmsg_one(&sock, 0).is_some();
        println!("    reply delivered while blocked: {got_a} (false = filter blocks)");

        println!("    phase B: same socket, filter passes all except Time Exceeded blocked");
        println!("    (pass-all + block(3) — echo replies must flow again):");
        let pass_echo = Icmp6Filter::block_all()
            .pass(ICMPV6_ECHO_REPLY)
            .block(ICMPV6_TIME_EXCEEDED);
        match set_icmp6_filter(&sock, &pass_echo) {
            Ok(()) => println!("    setsockopt(ICMPV6_FILTER) OK"),
            Err(e) => {
                println!("    setsockopt(ICMPV6_FILTER) FAILED: {e}");
                return;
            }
        }
        sock.send_to(&build_echo_request(0, 52), &dest)
            .expect("send");
        let got_b = recvmsg_one(&sock, 0).is_some();
        println!("    reply delivered after unblocking: {got_b} (true = SET-bit-means-BLOCK)");
        println!(
            "    => positive control {}",
            if !got_a && got_b {
                "PASSED: Linux semantics confirmed inverted vs BSD"
            } else {
                "INCONCLUSIVE — see raw results above"
            }
        );
    }

    /// [6] The make-or-break: unprivileged UDP6 traceroute via IPV6_RECVERR,
    /// mirroring ftr's v4 UDP mode. One socket per hop; ICMPv6 errors come
    /// back on each socket's error queue with the offender address.
    fn run_udp_traceroute() {
        println!(
            "\n[6] UDP6 + IPV6_RECVERR traceroute to {TARGET} \
             (ports {UDP_BASE_PORT}+hop, unprivileged):"
        );
        for hop in 1..=UDP_MAX_HOPS {
            let sock =
                Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP)).expect("UDP6 socket");
            sock.set_unicast_hops_v6(hop).expect("IPV6_UNICAST_HOPS");
            sock.set_recv_hoplimit_v6(true).expect("IPV6_RECVHOPLIMIT");
            set_recverr(&sock).expect("IPV6_RECVERR");
            let port = UDP_BASE_PORT + hop as u16;
            let dest = SockAddr::from(SocketAddrV6::new(TARGET, port, 0, 0));
            let sent_at = Instant::now();
            if let Err(e) = sock.send_to(b"ftr-linux-v6-spike", &dest) {
                println!("    hop {hop:2}: send failed: {e}");
                continue;
            }
            match wait_errqueue(&sock, sent_at + Duration::from_secs(2)) {
                Some(r) => {
                    let rtt = sent_at.elapsed();
                    let Some((ee, offender)) = r.ext_err else {
                        println!("    hop {hop:2}: errqueue msg without RECVERR cmsg?!");
                        continue;
                    };
                    let kind = match (ee.ee_type, ee.ee_code) {
                        (ICMPV6_TIME_EXCEEDED, _) => "time exceeded",
                        (ICMPV6_DEST_UNREACH, ICMPV6_UNREACH_PORT) => {
                            "port unreachable (DESTINATION)"
                        }
                        _ => "other",
                    };
                    println!(
                        "    hop {hop:2}: {} ee_type={} ee_code={} ee_errno={} [{kind}] \
                         hoplimit_cmsg={:?} rtt={:.1?}",
                        offender
                            .map(|a| a.to_string())
                            .unwrap_or_else(|| "<no offender>".into()),
                        ee.ee_type,
                        ee.ee_code,
                        ee.ee_errno,
                        r.hop_limit,
                        rtt
                    );
                    if ee.ee_type == ICMPV6_DEST_UNREACH && ee.ee_code == ICMPV6_UNREACH_PORT {
                        println!("    => DESTINATION REACHED at hop {hop} — UDP6 mode WORKS");
                        return;
                    }
                }
                None => println!("    hop {hop:2}: * (no ICMPv6 error within 2s)"),
            }
        }
        println!("    (scan ended without a port-unreachable from the target)");
    }

    /// Parse a Time Exceeded payload and return the embedded (id, seq) if
    /// the invoking packet was an ICMPv6 Echo. Layout as validated on macOS
    /// (docs/IPV6_DESIGN.md): 8 B ICMPv6 + fixed 40 B invoking IPv6 header
    /// (next_header must be 58) + 8 B invoking ICMPv6 echo header.
    fn parse_time_exceeded(bytes: &[u8]) -> Option<(u16, u16)> {
        if bytes.len() < 8 + 40 + 8 || bytes[8 + 6] != 58 {
            return None;
        }
        let inner = &bytes[48..56];
        Some((
            u16::from_be_bytes([inner[4], inner[5]]),
            u16::from_be_bytes([inner[6], inner[7]]),
        ))
    }

    /// Drain a raw socket's normal receive path until a Time Exceeded whose
    /// embedded id/seq match, or the deadline. Returns whether it matched.
    fn drain_for_te(sock: &Socket, id: u16, seq: u16) -> bool {
        let deadline = Instant::now() + RECV_TIMEOUT;
        sock.set_read_timeout(Some(Duration::from_millis(500)))
            .expect("timeout");
        while Instant::now() < deadline {
            let Some(r) = recvmsg_one(sock, 0) else {
                continue;
            };
            let ty = r.bytes.first().copied().unwrap_or(0);
            if ty == ICMPV6_TIME_EXCEEDED {
                if let Some((got_id, got_seq)) = parse_time_exceeded(&r.bytes) {
                    println!(
                        "    got TIME EXCEEDED from {:?} embedded id=0x{got_id:04x} \
                         seq={got_seq} (reply hoplimit cmsg: {:?})",
                        r.from, r.hop_limit
                    );
                    if got_id == id && got_seq == seq {
                        return true;
                    }
                }
            } else if ty != ICMPV6_ECHO_REPLY {
                println!("    (skipping unrelated ICMPv6 type {ty})");
            }
        }
        false
    }

    /// [7] RAW ICMPv6: only runs when the socket opens (root/CAP_NET_RAW).
    /// Answers: does the kernel checksum raw ICMPv6 sends? Does Time
    /// Exceeded arrive on the raw socket's NORMAL receive path (no errqueue
    /// needed)? And the ICMP6_FILTER positive control — Linux ties this
    /// option to raw sockets only ([5] shows ping sockets say ENOPROTOOPT).
    fn run_raw_tests() {
        println!("\n[7] RAW ICMPv6 socket tests:");
        let sock = match Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6)) {
            Ok(s) => s,
            Err(e) => {
                println!(
                    "    RAW socket unavailable ({e}) — needs root. Maintainer: run\n    \
                     sudo ./target/debug/examples/spike_linux_v6\n    \
                     (the spike auto-detects raw availability and runs this section)"
                );
                return;
            }
        };
        sock.set_read_timeout(Some(RECV_TIMEOUT)).expect("timeout");
        sock.set_recv_hoplimit_v6(true).expect("recvhoplimit");

        println!("    a: zero-checksum echo (does the kernel checksum raw v6 sends?):");
        let dest = SockAddr::from(SocketAddrV6::new(TARGET, 0, 0, 0));
        sock.send_to(&build_echo_request(0x7777, 1), &dest)
            .expect("send");
        let deadline = Instant::now() + RECV_TIMEOUT;
        let mut got_reply = false;
        sock.set_read_timeout(Some(Duration::from_millis(500)))
            .expect("timeout");
        while Instant::now() < deadline && !got_reply {
            let Some(r) = recvmsg_one(&sock, 0) else {
                continue;
            };
            if r.bytes.len() >= 8 && r.bytes[0] == ICMPV6_ECHO_REPLY {
                let id = u16::from_be_bytes([r.bytes[4], r.bytes[5]]);
                let seq = u16::from_be_bytes([r.bytes[6], r.bytes[7]]);
                println!(
                    "    got ECHO REPLY id=0x{id:04x} seq={seq} from {:?} — raw buffer \
                     also starts at the ICMPv6 header",
                    r.from
                );
                got_reply = id == 0x7777 && seq == 1;
            }
        }
        println!(
            "    => reply to zero-checksum raw send: {got_reply} \
             (true = kernel computes ICMPv6 checksums on raw too)"
        );

        println!("    b: hop-limited probe — Time Exceeded on NORMAL receive path?");
        sock.set_unicast_hops_v6(PROBE_HOP_LIMIT).expect("hops");
        sock.send_to(&build_echo_request(0x7777, 2), &dest)
            .expect("send");
        let saw_te = drain_for_te(&sock, 0x7777, 2);
        println!(
            "    => RAW socket {} Time Exceeded on the normal path (no errqueue needed)",
            if saw_te {
                "receives"
            } else {
                "did NOT receive"
            }
        );

        println!("    c: ICMP6_FILTER positive control on the raw socket:");
        println!("    phase A: pass-all + BLOCK Time Exceeded (bit 3 set); expect NO TE:");
        let block_te = Icmp6Filter::pass_all().block(ICMPV6_TIME_EXCEEDED);
        match set_icmp6_filter(&sock, &block_te) {
            Ok(()) => println!("    setsockopt(ICMPV6_FILTER) OK"),
            Err(e) => {
                println!("    setsockopt(ICMPV6_FILTER) FAILED: {e}");
                return;
            }
        }
        sock.send_to(&build_echo_request(0x7777, 3), &dest)
            .expect("send");
        let te_while_blocked = drain_for_te(&sock, 0x7777, 3);
        println!(
            "    => TE delivered while bit 3 SET: {te_while_blocked} (false = bit means BLOCK)"
        );

        println!("    phase B: pass-all (all bits clear); expect the TE again:");
        set_icmp6_filter(&sock, &Icmp6Filter::pass_all()).expect("filter");
        sock.send_to(&build_echo_request(0x7777, 4), &dest)
            .expect("send");
        let te_after_unblock = drain_for_te(&sock, 0x7777, 4);
        println!(
            "    => TE delivered with all bits CLEAR: {te_after_unblock} (true = clear means PASS)"
        );
        println!(
            "    => positive control {}",
            if !te_while_blocked && te_after_unblock {
                "PASSED: Linux ICMP6_FILTER semantics are INVERTED vs BSD (bit set = BLOCK)"
            } else {
                "INCONCLUSIVE — see raw results above"
            }
        );
    }

    /// Enable `IPV6_RECVERR` (socket2 has no wrapper for it).
    fn set_recverr(socket: &Socket) -> std::io::Result<()> {
        let on: libc::c_int = 1;
        // SAFETY: fd valid for socket lifetime; option value is a c_int.
        let rc = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_IPV6,
                IPV6_RECVERR,
                (&raw const on).cast(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if rc == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }

    /// Apply an ICMP6_FILTER via raw setsockopt (no socket2 API; see
    /// rust-lang/socket2#199).
    fn set_icmp6_filter(socket: &Socket, filter: &Icmp6Filter) -> std::io::Result<()> {
        // SAFETY: fd valid for socket lifetime; buffer is a repr(C) mirror
        // of struct icmp6_filter with the documented 32-byte size.
        let rc = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_ICMPV6,
                ICMPV6_FILTER,
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

    pub fn run() {
        let euid = unsafe { libc::geteuid() };
        let egid = unsafe { libc::getegid() };
        println!(
            "=== spike_linux_v6: Linux ICMPv6/UDP6 kernel behavior (euid={euid} egid={egid}) ==="
        );
        println!(
            "    net.ipv4.ping_group_range = {} (gates ICMPv6 ping sockets too)",
            ping_group_range()
        );

        println!("\n[1] unprivileged socket availability:");
        match Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6)) {
            Ok(_) => println!("    RAW ICMPv6: OK (running privileged or CAP_NET_RAW)"),
            Err(e) => println!("    RAW ICMPv6: {e} (os error {:?})", e.raw_os_error()),
        }
        let ping_available = match Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::ICMPV6)) {
            Ok(_) => {
                println!("    DGRAM ICMPv6 (ping socket): OK");
                true
            }
            Err(e) => {
                println!(
                    "    DGRAM ICMPv6 (ping socket): {e} (os error {:?})",
                    e.raw_os_error()
                );
                println!(
                    "    to enable, the admin must widen the range, e.g.:\n    \
                     sudo sysctl -w net.ipv4.ping_group_range=\"0 2147483647\""
                );
                false
            }
        };

        if ping_available {
            run_ident_rewrite_test();
            run_demux_test();
            run_ping_time_exceeded_test();
            run_filter_test();
        } else {
            println!("\n[2-5] ping-socket tests skipped (socket unavailable, see [1])");
        }

        run_raw_tests();
        run_udp_traceroute();

        println!("\n=== spike_linux_v6 done ===");
    }
}

#[cfg(target_os = "linux")]
fn main() {
    spike::run();
}

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("spike_linux_v6: Linux-only spike (validates ping-socket and IPV6_RECVERR behavior)");
}
