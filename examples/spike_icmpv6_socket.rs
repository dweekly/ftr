//! Spike: baseline ICMPv6 socket behavior for future IPv6 traceroute support.
//!
//! Empirically answers, on the machine it runs on (primary target: macOS):
//!
//! 1. Can we open `Domain::IPV6` / `Type::DGRAM` / `Protocol::ICMPV6`
//!    WITHOUT root? (SwiftFTR relies on Darwin allowing this.)
//! 2. Does `Type::RAW` / `Protocol::ICMPV6` require root (expect EPERM
//!    unprivileged)?
//! 3. Does the kernel compute the ICMPv6 checksum for us on the DGRAM
//!    socket? (It must — the ICMPv6 checksum covers the IPv6 pseudo-header,
//!    whose source address userspace may not know before send.) We test by
//!    sending an Echo Request with a zeroed checksum field: a reply proves
//!    the checksum was filled in by the kernel.
//! 4. Does the received buffer start directly at the ICMPv6 header, i.e.
//!    NO IPv6 header is prepended (unlike IPv4 raw sockets, per RFC 3542)?
//! 5. Does the kernel demux DGRAM ICMPv6 Echo Replies by ICMP identifier
//!    (two sockets with different identifiers each receive only their own
//!    reply)? SwiftFTR observed this for IPv4 on Darwin; confirm for v6.
//!
//! Run: `cargo run --example spike_icmpv6_socket`
//!
//! Findings are recorded in docs/IPV6_DESIGN.md. This spike stays in-repo as
//! a permanent diagnostic: re-run it if kernel/OS behavior is in question.

/// ICMPv6 Echo Request message type (RFC 4443 section 4.1).
const ICMPV6_ECHO_REQUEST: u8 = 128;
/// ICMPv6 Echo Reply message type (RFC 4443 section 4.2).
const ICMPV6_ECHO_REPLY: u8 = 129;
/// How long to wait for each reply. Google public DNS answers in ~5 ms from
/// most networks; 3 s is a generous bound that keeps the spike fast.
const RECV_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

#[cfg(any(target_os = "macos", target_os = "linux", target_os = "freebsd"))]
mod spike {
    use super::{ICMPV6_ECHO_REPLY, ICMPV6_ECHO_REQUEST, RECV_TIMEOUT};
    use socket2::{Domain, Protocol, SockAddr, Socket, Type};
    use std::mem::MaybeUninit;
    use std::net::{Ipv6Addr, SocketAddrV6};

    /// Well-known Google Public DNS IPv6 anycast address — a reliable
    /// ICMPv6 echo responder for connectivity spikes.
    const TARGET: Ipv6Addr = Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888);

    /// Build an ICMPv6 Echo Request with a ZEROED checksum. If the kernel
    /// does not compute the checksum for us, this packet is invalid and no
    /// reply will come back — that absence is itself a finding.
    fn build_echo_request(identifier: u16, sequence: u16) -> Vec<u8> {
        let mut pkt = vec![
            ICMPV6_ECHO_REQUEST, // type
            0,                   // code
            0,
            0, // checksum: deliberately zero — testing kernel fill-in
        ];
        pkt.extend_from_slice(&identifier.to_be_bytes());
        pkt.extend_from_slice(&sequence.to_be_bytes());
        pkt.extend_from_slice(b"ftr-ipv6-spike"); // arbitrary payload
        pkt
    }

    /// Receive one datagram, returning (bytes, sender). `None` on timeout.
    fn recv_one(socket: &Socket) -> Option<(Vec<u8>, Option<SocketAddrV6>)> {
        let mut buf = [MaybeUninit::<u8>::uninit(); 1500];
        match socket.recv_from(&mut buf) {
            Ok((n, addr)) => {
                // SAFETY: recv_from initialized the first `n` bytes.
                let bytes: Vec<u8> = buf[..n]
                    .iter()
                    .map(|b| unsafe { b.assume_init() })
                    .collect();
                Some((bytes, addr.as_socket_ipv6()))
            }
            Err(e) => {
                println!("    recv: {e} (timeout or error)");
                None
            }
        }
    }

    fn describe_reply(bytes: &[u8]) {
        if bytes.len() < 8 {
            println!("    reply too short to parse: {} bytes", bytes.len());
            return;
        }
        let first = bytes[0];
        println!(
            "    first byte = {first} (0x{first:02x}) — {}",
            if first == ICMPV6_ECHO_REPLY {
                "ICMPv6 Echo Reply: buffer starts at ICMPv6 header, NO IPv6 header prepended"
            } else if first >> 4 == 6 {
                "looks like an IPv6 header version nibble — IPv6 header IS prepended"
            } else {
                "unexpected"
            }
        );
        let checksum = u16::from_be_bytes([bytes[2], bytes[3]]);
        let id = u16::from_be_bytes([bytes[4], bytes[5]]);
        let seq = u16::from_be_bytes([bytes[6], bytes[7]]);
        println!("    checksum=0x{checksum:04x} identifier=0x{id:04x} sequence={seq}");
    }

    pub fn run() {
        println!(
            "=== spike_icmpv6_socket: ICMPv6 socket basics (euid={}) ===",
            unsafe { libc::geteuid() }
        );

        // ---- Q2: RAW ICMPv6 without root ----
        println!("\n[1] Socket::new(IPV6, RAW, ICMPV6):");
        match Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6)) {
            Ok(_) => println!("    OK — raw ICMPv6 socket opened (running as root?)"),
            Err(e) => println!(
                "    FAILED: {e} (os error {:?}) — raw needs root, as expected",
                e.raw_os_error()
            ),
        }

        // ---- Q1: DGRAM ICMPv6 without root ----
        println!("\n[2] Socket::new(IPV6, DGRAM, ICMPV6):");
        let socket = match Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::ICMPV6)) {
            Ok(s) => {
                println!("    OK — unprivileged DGRAM ICMPv6 socket opened");
                s
            }
            Err(e) => {
                println!(
                    "    FAILED: {e} (os error {:?}) — DGRAM ICMPv6 unavailable unprivileged",
                    e.raw_os_error()
                );
                return;
            }
        };
        socket
            .set_read_timeout(Some(RECV_TIMEOUT))
            .expect("set_read_timeout");

        // ---- Q3 + Q4: zero-checksum echo, reply framing ----
        println!("\n[3] Echo Request to {TARGET} with ZEROED checksum (id=0x1234 seq=1):");
        let dest = SockAddr::from(SocketAddrV6::new(TARGET, 0, 0, 0));
        let pkt = build_echo_request(0x1234, 1);
        match socket.send_to(&pkt, &dest) {
            Ok(n) => println!("    sent {n} bytes"),
            Err(e) => {
                println!("    send failed: {e}");
                return;
            }
        }
        match recv_one(&socket) {
            Some((bytes, from)) => {
                println!(
                    "    received {} bytes from {:?}",
                    bytes.len(),
                    from.map(|a| *a.ip())
                );
                describe_reply(&bytes);
                println!(
                    "    => reply came back despite zero checksum on send: \
                     kernel computed the ICMPv6 checksum"
                );
            }
            None => println!(
                "    => NO reply. Either the kernel does NOT fill the checksum, \
                 or no v6 connectivity — cross-check with `ping6 {TARGET}`"
            ),
        }

        // ---- Q5: identifier-based demux across two sockets ----
        println!("\n[4] Demux test: two DGRAM sockets, ids 0x1111 and 0x2222:");
        let sock_a =
            Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::ICMPV6)).expect("socket A");
        let sock_b =
            Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::ICMPV6)).expect("socket B");
        sock_a
            .set_read_timeout(Some(RECV_TIMEOUT))
            .expect("timeout A");
        sock_b
            .set_read_timeout(Some(RECV_TIMEOUT))
            .expect("timeout B");
        sock_a
            .send_to(&build_echo_request(0x1111, 7), &dest)
            .expect("send A");
        sock_b
            .send_to(&build_echo_request(0x2222, 8), &dest)
            .expect("send B");

        // Drain each socket completely (recv until timeout) so we can see
        // exactly which replies were delivered where.
        for (name, sock, want_id) in [("A", &sock_a, 0x1111u16), ("B", &sock_b, 0x2222u16)] {
            println!("    socket {name} (sent id=0x{want_id:04x}), draining:");
            let mut got_own = false;
            let mut got_foreign = false;
            while let Some((bytes, _)) = recv_one(sock) {
                if bytes.len() >= 8 {
                    let id = u16::from_be_bytes([bytes[4], bytes[5]]);
                    let seq = u16::from_be_bytes([bytes[6], bytes[7]]);
                    let own = id == want_id;
                    got_own |= own;
                    got_foreign |= !own;
                    println!(
                        "      got type={} id=0x{id:04x} seq={seq} ({})",
                        bytes[0],
                        if own { "own" } else { "FOREIGN" }
                    );
                } else {
                    println!("      short packet: {} bytes", bytes.len());
                }
            }
            println!(
                "      => own reply: {got_own}, foreign reply: {got_foreign} — {}",
                if got_foreign {
                    "kernel does NOT demux by identifier; userspace must filter"
                } else if got_own {
                    "only own reply seen: kernel demuxes by identifier"
                } else {
                    "no replies seen"
                }
            );
        }
        println!("\n=== spike_icmpv6_socket done ===");
    }
}

#[cfg(any(target_os = "macos", target_os = "linux", target_os = "freebsd"))]
fn main() {
    spike::run();
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "freebsd")))]
fn main() {
    println!("spike_icmpv6_socket: only implemented for macOS/Linux/FreeBSD");
}
