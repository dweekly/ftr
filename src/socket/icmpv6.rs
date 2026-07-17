//! Manual ICMPv6 packet construction and parsing
//!
//! Companion to [`super::icmp`] for IPv6 traceroute. All formats follow
//! RFC 4443 (ICMPv6) and RFC 8200 (IPv6 header). Two deliberate differences
//! from the IPv4 codec, both validated live in `docs/IPV6_DESIGN.md`:
//!
//! 1. **Checksum is left zero on send.** The ICMPv6 checksum covers the IPv6
//!    pseudo-header (RFC 4443 section 2.3), whose source address userspace
//!    may not know before send; the kernel fills it in on DGRAM ICMPv6
//!    sockets (validated on macOS by `examples/spike_icmpv6_socket.rs`).
//! 2. **Received buffers start at the ICMPv6 header.** Unlike IPv4 raw
//!    sockets, the kernel never prepends the IPv6 header (RFC 3542 section
//!    2.6 behavior, validated by the same spike), so there is no
//!    variable-length IP header to skip.

use std::net::Ipv6Addr;

// ICMPv6 type constants (RFC 4443)
/// ICMPv6 Destination Unreachable (type 1, RFC 4443 section 3.1)
pub const ICMPV6_DEST_UNREACHABLE: u8 = 1;
/// ICMPv6 Time Exceeded (type 3, RFC 4443 section 3.3)
pub const ICMPV6_TIME_EXCEEDED: u8 = 3;
/// ICMPv6 Echo Request (type 128, RFC 4443 section 4.1)
pub const ICMPV6_ECHO_REQUEST: u8 = 128;
/// ICMPv6 Echo Reply (type 129, RFC 4443 section 4.2)
pub const ICMPV6_ECHO_REPLY: u8 = 129;

/// ICMPv6 header size in bytes: type(1) + code(1) + checksum(2) +
/// message-specific(4) — for echo, the 4 bytes are identifier + sequence
/// (RFC 4443 section 2.1).
pub const ICMPV6_HEADER_SIZE: usize = 8;

/// IPv6 header size in bytes — fixed, no options/IHL (RFC 8200 section 3).
pub const IPV6_HEADER_SIZE: usize = 40;

/// IPv6 Next Header value for ICMPv6 (RFC 8200 / IANA protocol number 58).
pub const IPV6_NEXT_HEADER_ICMPV6: u8 = 58;

/// Minimum length of an ICMPv6 error message that embeds one of our echo
/// probes: 8-byte error header + 40-byte invoking IPv6 header + 8-byte
/// invoking ICMPv6 echo header (RFC 4443 section 3.3 layout, validated by
/// `examples/spike_traceroute6.rs`).
const MIN_ERROR_WITH_ECHO_LEN: usize = ICMPV6_HEADER_SIZE + IPV6_HEADER_SIZE + ICMPV6_HEADER_SIZE;

/// Build an ICMPv6 Echo Request packet.
///
/// Layout: [type(1), code(1), checksum(2), identifier(2), sequence(2),
/// payload(N)]. The checksum is deliberately left as zero: on DGRAM ICMPv6
/// sockets the kernel computes it (it requires the IPv6 pseudo-header, which
/// only the kernel knows at send time). Do NOT use this for a hypothetical
/// send path where the kernel does not checksum.
pub fn build_echo_request_v6(identifier: u16, sequence: u16, payload: &[u8]) -> Vec<u8> {
    let mut buf = vec![0u8; ICMPV6_HEADER_SIZE + payload.len()];
    buf[0] = ICMPV6_ECHO_REQUEST; // type
    buf[1] = 0; // code
    // checksum at [2..4] stays zero — kernel fills it in on DGRAM send
    buf[4..6].copy_from_slice(&identifier.to_be_bytes());
    buf[6..8].copy_from_slice(&sequence.to_be_bytes());
    buf[ICMPV6_HEADER_SIZE..].copy_from_slice(payload);
    buf
}

/// Parsed ICMPv6 header fields (type and code).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Icmpv6Header {
    /// ICMPv6 message type
    pub icmpv6_type: u8,
    /// ICMPv6 message code
    pub icmpv6_code: u8,
}

/// Parse the type and code from an ICMPv6 packet (buffer starting at the
/// ICMPv6 header — no IPv6 header prefix on DGRAM/raw ICMPv6 sockets).
pub fn parse_icmpv6_header(data: &[u8]) -> Option<Icmpv6Header> {
    if data.len() < 4 {
        return None;
    }
    Some(Icmpv6Header {
        icmpv6_type: data[0],
        icmpv6_code: data[1],
    })
}

/// Extract identifier and sequence number from an ICMPv6 Echo Reply.
///
/// Returns `None` if the buffer is too short or is not an Echo Reply.
/// The caller MUST validate the identifier against its own: Darwin delivers
/// every inbound ICMPv6 packet to every DGRAM ICMPv6 socket (no kernel
/// demux by echo identifier — validated finding in `docs/IPV6_DESIGN.md`).
pub fn parse_echo_reply_v6(data: &[u8]) -> Option<(u16, u16)> {
    if data.len() < ICMPV6_HEADER_SIZE || data[0] != ICMPV6_ECHO_REPLY {
        return None;
    }
    let identifier = u16::from_be_bytes([data[4], data[5]]);
    let sequence = u16::from_be_bytes([data[6], data[7]]);
    Some((identifier, sequence))
}

/// The invoking echo probe recovered from an ICMPv6 error message
/// (Time Exceeded or Destination Unreachable).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmbeddedProbe {
    /// Identifier of the invoking Echo Request
    pub identifier: u16,
    /// Sequence number of the invoking Echo Request
    pub sequence: u16,
    /// Destination the invoking packet was sent to (from the embedded IPv6
    /// header) — lets callers confirm the error refers to their probe's
    /// target, not another flow with a colliding id/seq.
    pub destination: Ipv6Addr,
}

/// Parse the embedded invoking probe out of an ICMPv6 error message.
///
/// Layout (RFC 4443 section 3.3, validated live): 8-byte ICMPv6 error
/// header, then as much of the invoking packet as fits — for our echo
/// probes that is the fixed 40-byte invoking IPv6 header followed by the
/// 8-byte invoking ICMPv6 echo header.
///
/// Returns `None` unless every layer checks out: outer type is Time
/// Exceeded or Destination Unreachable, embedded IP version is 6, embedded
/// Next Header is ICMPv6 (58), and the embedded message is an Echo Request.
/// As with echo replies, the caller MUST validate the embedded identifier
/// (and sequence) against its own probes.
pub fn parse_embedded_probe(data: &[u8]) -> Option<EmbeddedProbe> {
    if data.len() < MIN_ERROR_WITH_ECHO_LEN {
        return None;
    }
    let outer_type = data[0];
    if outer_type != ICMPV6_TIME_EXCEEDED && outer_type != ICMPV6_DEST_UNREACHABLE {
        return None;
    }

    // Embedded (invoking) IPv6 header at fixed offset 8.
    let inner_ip = &data[ICMPV6_HEADER_SIZE..ICMPV6_HEADER_SIZE + IPV6_HEADER_SIZE];
    if inner_ip[0] >> 4 != 6 {
        return None; // version nibble must be 6
    }
    // Next Header at byte 6 of the IPv6 header (RFC 8200 section 3). We only
    // ever send bare ICMPv6 echoes (no extension headers), so anything else
    // is not our probe.
    if inner_ip[6] != IPV6_NEXT_HEADER_ICMPV6 {
        return None;
    }
    let destination = Ipv6Addr::from(<[u8; 16]>::try_from(&inner_ip[24..40]).ok()?);

    // Embedded (invoking) ICMPv6 echo header at fixed offset 48.
    let inner_icmp = &data[ICMPV6_HEADER_SIZE + IPV6_HEADER_SIZE..MIN_ERROR_WITH_ECHO_LEN];
    if inner_icmp[0] != ICMPV6_ECHO_REQUEST {
        return None;
    }
    Some(EmbeddedProbe {
        identifier: u16::from_be_bytes([inner_icmp[4], inner_icmp[5]]),
        sequence: u16::from_be_bytes([inner_icmp[6], inner_icmp[7]]),
        destination,
    })
}

/// Whether an ICMPv6 type is Neighbor Discovery / Router Discovery chatter
/// (RFC 4861 types 133-137: RS, RA, NS, NA, Redirect).
///
/// A DGRAM ICMPv6 socket on Darwin receives this link noise interleaved
/// with echo replies (observed live — see `docs/IPV6_DESIGN.md`); receive
/// loops should skip these silently. An `ICMP6_FILTER` passing only types
/// 1/3/129 sheds them in the kernel, but that filter is best-effort — this
/// predicate keeps the userspace path correct regardless.
pub fn is_ndp(icmpv6_type: u8) -> bool {
    (133..=137).contains(&icmpv6_type)
}

/// Format an IPv6 address with its RFC 4007 zone identifier, if any.
///
/// The address itself renders through `Ipv6Addr`'s `Display`, which is
/// RFC 5952 canonical (lowercase, longest zero run compressed to `::`) —
/// never hand-format hextets. A non-zero scope id is appended as `%zone`.
/// On Unix platforms with `libc` available the interface name is used
/// (`fe80::1%en0`); otherwise, or if the index has no name, the numeric
/// form (`fe80::1%5`) — both are valid RFC 4007 zone identifiers.
pub fn format_ipv6_with_zone(addr: Ipv6Addr, scope_id: u32) -> String {
    if scope_id == 0 {
        return addr.to_string();
    }
    #[cfg(any(
        target_os = "macos",
        target_os = "linux",
        target_os = "freebsd",
        target_os = "openbsd"
    ))]
    {
        // IF_NAMESIZE-sized buffer per POSIX if_indextoname(3).
        let mut name_buf = [0u8; libc::IF_NAMESIZE];
        // SAFETY: name_buf is a valid, writable IF_NAMESIZE-byte buffer for
        // the duration of the call, as if_indextoname requires.
        let ret = unsafe { libc::if_indextoname(scope_id, name_buf.as_mut_ptr().cast()) };
        if !ret.is_null() {
            let len = name_buf.iter().position(|&b| b == 0).unwrap_or(0);
            if let Ok(name) = std::str::from_utf8(&name_buf[..len]) {
                if !name.is_empty() {
                    return format!("{addr}%{name}");
                }
            }
        }
    }
    format!("{addr}%{scope_id}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a synthetic ICMPv6 error message (Time Exceeded or Destination
    /// Unreachable) embedding an invoking IPv6+ICMPv6 echo, mirroring what
    /// routers send back (observed layout in docs/IPV6_DESIGN.md).
    fn build_error_message(
        outer_type: u8,
        inner_version: u8,
        inner_next_header: u8,
        inner_icmp_type: u8,
        identifier: u16,
        sequence: u16,
        dst: Ipv6Addr,
    ) -> Vec<u8> {
        let mut buf = vec![0u8; MIN_ERROR_WITH_ECHO_LEN];
        buf[0] = outer_type;
        // bytes 1..8: code, checksum, unused — zero is fine
        let inner_ip = &mut buf[8..48];
        inner_ip[0] = inner_version << 4;
        inner_ip[6] = inner_next_header;
        inner_ip[7] = 1; // hop limit decremented to 1, as routers report
        // src (bytes 8..24) left zero; dst at 24..40
        inner_ip[24..40].copy_from_slice(&dst.octets());
        let inner_icmp = &mut buf[48..56];
        inner_icmp[0] = inner_icmp_type;
        inner_icmp[4..6].copy_from_slice(&identifier.to_be_bytes());
        inner_icmp[6..8].copy_from_slice(&sequence.to_be_bytes());
        buf
    }

    const GOOGLE_V6: Ipv6Addr = Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888);

    #[test]
    fn test_build_echo_request_v6_layout() {
        let pkt = build_echo_request_v6(0x1234, 0x0007, &[0xAA, 0xBB]);
        assert_eq!(pkt.len(), 10);
        assert_eq!(pkt[0], ICMPV6_ECHO_REQUEST);
        assert_eq!(pkt[1], 0); // code
        assert_eq!(&pkt[2..4], &[0, 0]); // checksum left for the kernel
        assert_eq!(u16::from_be_bytes([pkt[4], pkt[5]]), 0x1234);
        assert_eq!(u16::from_be_bytes([pkt[6], pkt[7]]), 0x0007);
        assert_eq!(&pkt[8..], &[0xAA, 0xBB]);
    }

    #[test]
    fn test_build_echo_request_v6_empty_payload() {
        let pkt = build_echo_request_v6(1, 2, &[]);
        assert_eq!(pkt.len(), ICMPV6_HEADER_SIZE);
    }

    #[test]
    fn test_parse_icmpv6_header() {
        let hdr = parse_icmpv6_header(&[ICMPV6_TIME_EXCEEDED, 0, 0xde, 0xad])
            .expect("4-byte header should parse");
        assert_eq!(hdr.icmpv6_type, ICMPV6_TIME_EXCEEDED);
        assert_eq!(hdr.icmpv6_code, 0);
        assert!(parse_icmpv6_header(&[1, 2, 3]).is_none()); // too short
    }

    #[test]
    fn test_parse_echo_reply_v6() {
        let mut data = vec![0u8; ICMPV6_HEADER_SIZE];
        data[0] = ICMPV6_ECHO_REPLY;
        data[4..6].copy_from_slice(&0xBEEFu16.to_be_bytes());
        data[6..8].copy_from_slice(&42u16.to_be_bytes());
        assert_eq!(parse_echo_reply_v6(&data), Some((0xBEEF, 42)));
    }

    #[test]
    fn test_parse_echo_reply_v6_rejects_wrong_type_and_short() {
        let mut data = vec![0u8; ICMPV6_HEADER_SIZE];
        data[0] = ICMPV6_ECHO_REQUEST; // request, not reply
        assert!(parse_echo_reply_v6(&data).is_none());
        assert!(parse_echo_reply_v6(&[ICMPV6_ECHO_REPLY, 0, 0, 0]).is_none());
    }

    #[test]
    fn test_parse_embedded_probe_time_exceeded() {
        let msg = build_error_message(
            ICMPV6_TIME_EXCEEDED,
            6,
            IPV6_NEXT_HEADER_ICMPV6,
            ICMPV6_ECHO_REQUEST,
            0x3333,
            9,
            GOOGLE_V6,
        );
        let probe = parse_embedded_probe(&msg).expect("valid TE should parse");
        assert_eq!(probe.identifier, 0x3333);
        assert_eq!(probe.sequence, 9);
        assert_eq!(probe.destination, GOOGLE_V6);
    }

    #[test]
    fn test_parse_embedded_probe_dest_unreachable() {
        let msg = build_error_message(
            ICMPV6_DEST_UNREACHABLE,
            6,
            IPV6_NEXT_HEADER_ICMPV6,
            ICMPV6_ECHO_REQUEST,
            7,
            8,
            GOOGLE_V6,
        );
        let probe = parse_embedded_probe(&msg).expect("valid unreachable should parse");
        assert_eq!((probe.identifier, probe.sequence), (7, 8));
    }

    #[test]
    fn test_parse_embedded_probe_rejects_echo_reply_outer_type() {
        let msg = build_error_message(
            ICMPV6_ECHO_REPLY, // not an error type
            6,
            IPV6_NEXT_HEADER_ICMPV6,
            ICMPV6_ECHO_REQUEST,
            1,
            1,
            GOOGLE_V6,
        );
        assert!(parse_embedded_probe(&msg).is_none());
    }

    #[test]
    fn test_parse_embedded_probe_rejects_bad_version() {
        let msg = build_error_message(
            ICMPV6_TIME_EXCEEDED,
            4, // embedded packet claims IPv4
            IPV6_NEXT_HEADER_ICMPV6,
            ICMPV6_ECHO_REQUEST,
            1,
            1,
            GOOGLE_V6,
        );
        assert!(parse_embedded_probe(&msg).is_none());
    }

    #[test]
    fn test_parse_embedded_probe_rejects_non_icmpv6_next_header() {
        let msg = build_error_message(
            ICMPV6_TIME_EXCEEDED,
            6,
            17, // UDP — some other tool's probe expired, not ours
            ICMPV6_ECHO_REQUEST,
            1,
            1,
            GOOGLE_V6,
        );
        assert!(parse_embedded_probe(&msg).is_none());
    }

    #[test]
    fn test_parse_embedded_probe_rejects_non_echo_inner() {
        let msg = build_error_message(
            ICMPV6_TIME_EXCEEDED,
            6,
            IPV6_NEXT_HEADER_ICMPV6,
            ICMPV6_ECHO_REPLY, // embedded packet is a reply, not our request
            1,
            1,
            GOOGLE_V6,
        );
        assert!(parse_embedded_probe(&msg).is_none());
    }

    #[test]
    fn test_parse_embedded_probe_rejects_truncated() {
        let msg = build_error_message(
            ICMPV6_TIME_EXCEEDED,
            6,
            IPV6_NEXT_HEADER_ICMPV6,
            ICMPV6_ECHO_REQUEST,
            1,
            1,
            GOOGLE_V6,
        );
        // One byte short of embedding the full echo header.
        assert!(parse_embedded_probe(&msg[..MIN_ERROR_WITH_ECHO_LEN - 1]).is_none());
    }

    #[test]
    fn test_is_ndp_covers_discovery_types_only() {
        // RFC 4861: RS=133, RA=134, NS=135, NA=136, Redirect=137 — all seen
        // live on a DGRAM ICMPv6 socket (docs/IPV6_DESIGN.md).
        for ty in 133..=137u8 {
            assert!(is_ndp(ty), "type {ty} is NDP");
        }
        for ty in [
            ICMPV6_DEST_UNREACHABLE,
            ICMPV6_TIME_EXCEEDED,
            ICMPV6_ECHO_REQUEST,
            ICMPV6_ECHO_REPLY,
            132,
            138,
        ] {
            assert!(!is_ndp(ty), "type {ty} is not NDP");
        }
    }

    /// Address-contract test: Rust's `Ipv6Addr` `Display` must emit RFC 5952
    /// canonical form (lowercase, longest zero run compressed to `::`) —
    /// this is what ftr's design doc commits to for all v6 address strings.
    #[test]
    fn test_ipv6_display_is_rfc5952_canonical() {
        let cases: [(Ipv6Addr, &str); 7] = [
            (Ipv6Addr::UNSPECIFIED, "::"),
            (Ipv6Addr::LOCALHOST, "::1"),
            (GOOGLE_V6, "2001:4860:4860::8888"),
            // Longest zero run compressed, not the first shorter one
            (
                Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 1),
                "2001:db8:0:1::1",
            ),
            // Lowercase hex digits (RFC 5952 section 4.3)
            (
                Ipv6Addr::new(0x2001, 0xDB8, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF),
                "2001:db8:a:b:c:d:e:f",
            ),
            // IPv4-mapped renders with dotted quad
            (
                Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x0102, 0x0304),
                "::ffff:1.2.3.4",
            ),
            // Single zero group is NOT compressed to :: (RFC 5952 4.2.2)
            (
                Ipv6Addr::new(0x2001, 0xdb8, 1, 1, 1, 1, 0, 1),
                "2001:db8:1:1:1:1:0:1",
            ),
        ];
        for (addr, want) in cases {
            assert_eq!(addr.to_string(), want);
            // And the canonical string round-trips.
            assert_eq!(want.parse::<Ipv6Addr>().expect("round-trip parse"), addr);
        }
    }

    #[test]
    fn test_format_ipv6_with_zone() {
        let ll = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        // Zero scope id: plain canonical address, no % suffix.
        assert_eq!(format_ipv6_with_zone(ll, 0), "fe80::1");
        // Loopback interface index 1 exists on every Unix system; the zone
        // must be appended (as a name like "lo0"/"lo" or numerically), never
        // stripped.
        let formatted = format_ipv6_with_zone(ll, 1);
        let (addr_part, zone) = formatted
            .split_once('%')
            .expect("non-zero scope must render a %zone suffix");
        assert_eq!(addr_part, "fe80::1");
        assert!(!zone.is_empty());
        // An index that cannot correspond to a real interface falls back to
        // the numeric RFC 4007 zone form.
        assert_eq!(
            format_ipv6_with_zone(ll, 0x7fff_fff0),
            format!("fe80::1%{}", 0x7fff_fff0)
        );
    }
}
