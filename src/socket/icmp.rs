//! Manual ICMP and IPv4 packet construction and parsing
//!
//! Replaces pnet for the small subset of packet operations ftr needs:
//! ICMP echo request construction, IPv4 header parsing, and ICMP response parsing.
//! All formats follow RFC 791 (IPv4) and RFC 792 (ICMP).

use std::net::Ipv4Addr;

// ICMP type constants (RFC 792)
/// ICMP Echo Reply (type 0)
pub const ICMP_ECHO_REPLY: u8 = 0;
/// ICMP Destination Unreachable (type 3)
pub const ICMP_DEST_UNREACHABLE: u8 = 3;
/// ICMP Echo Request (type 8)
pub const ICMP_ECHO_REQUEST: u8 = 8;
/// ICMP Time Exceeded (type 11)
pub const ICMP_TIME_EXCEEDED: u8 = 11;

/// ICMP header size in bytes (type + code + checksum + id + seq)
const ICMP_HEADER_SIZE: usize = 8;

/// Build an ICMP Echo Request packet.
///
/// Returns a complete ICMP packet with header and payload, ready to send.
/// Layout: [type(1), code(1), checksum(2), identifier(2), sequence(2), payload(N)]
pub fn build_echo_request(identifier: u16, sequence: u16, payload: &[u8]) -> Vec<u8> {
    let total_len = ICMP_HEADER_SIZE + payload.len();
    let mut buf = vec![0u8; total_len];

    buf[0] = ICMP_ECHO_REQUEST; // type
    buf[1] = 0; // code
    // checksum at [2..4] — filled below
    buf[4..6].copy_from_slice(&identifier.to_be_bytes());
    buf[6..8].copy_from_slice(&sequence.to_be_bytes());
    buf[ICMP_HEADER_SIZE..].copy_from_slice(payload);

    let cksum = internet_checksum(&buf);
    buf[2..4].copy_from_slice(&cksum.to_be_bytes());

    buf
}

/// Minimum packet size for an ICMP echo request (header only, no payload).
pub const fn echo_request_min_size() -> usize {
    ICMP_HEADER_SIZE
}

/// Parse an IPv4 header to extract the payload offset and source address.
///
/// Returns `(header_length_bytes, source_addr)` or `None` if the buffer is too short.
pub fn parse_ipv4_header(data: &[u8]) -> Option<(usize, Ipv4Addr)> {
    if data.len() < 20 {
        return None;
    }
    // IHL is the lower 4 bits of byte 0, in 32-bit words
    let ihl = (data[0] & 0x0F) as usize * 4;
    if data.len() < ihl {
        return None;
    }
    let src = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
    Some((ihl, src))
}

/// Get the payload (everything after the IPv4 header) from a raw IP packet.
pub fn ipv4_payload(data: &[u8]) -> Option<&[u8]> {
    let (hdr_len, _) = parse_ipv4_header(data)?;
    if data.len() > hdr_len {
        Some(&data[hdr_len..])
    } else {
        None
    }
}

/// Parsed ICMP packet header fields.
#[derive(Debug, Clone)]
pub struct IcmpHeader {
    /// ICMP message type
    pub icmp_type: u8,
    /// ICMP message code
    pub icmp_code: u8,
}

/// Parse the type and code from an ICMP packet.
pub fn parse_icmp_header(data: &[u8]) -> Option<IcmpHeader> {
    if data.len() < 4 {
        return None;
    }
    Some(IcmpHeader {
        icmp_type: data[0],
        icmp_code: data[1],
    })
}

/// Extract identifier and sequence number from an ICMP Echo Reply packet.
///
/// The echo reply has the same layout as echo request:
/// [type(1), code(1), checksum(2), identifier(2), sequence(2), ...]
pub fn parse_echo_reply(data: &[u8]) -> Option<(u16, u16)> {
    if data.len() < ICMP_HEADER_SIZE {
        return None;
    }
    let identifier = u16::from_be_bytes([data[4], data[5]]);
    let sequence = u16::from_be_bytes([data[6], data[7]]);
    Some((identifier, sequence))
}

/// Compute the RFC 1071 internet checksum over a byte buffer.
///
/// Used for ICMP checksum calculation. The checksum field in the
/// buffer should be zero before calling this function.
pub fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;

    // Sum 16-bit words
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }

    // Handle odd byte
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }

    // Fold 32-bit sum to 16 bits
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !sum as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_echo_request() {
        let pkt = build_echo_request(0x1234, 0x0001, &[0xAA, 0xBB, 0xCC, 0xDD]);
        assert_eq!(pkt[0], ICMP_ECHO_REQUEST);
        assert_eq!(pkt[1], 0); // code
        assert_eq!(u16::from_be_bytes([pkt[4], pkt[5]]), 0x1234); // identifier
        assert_eq!(u16::from_be_bytes([pkt[6], pkt[7]]), 0x0001); // sequence
        assert_eq!(&pkt[8..], &[0xAA, 0xBB, 0xCC, 0xDD]); // payload

        // Verify checksum: recomputing over the entire packet should yield 0
        assert_eq!(internet_checksum(&pkt), 0);
    }

    #[test]
    fn test_internet_checksum() {
        // RFC 1071 example: the checksum of a valid packet is 0
        let pkt = build_echo_request(0, 0, &[]);
        assert_eq!(internet_checksum(&pkt), 0);
    }

    #[test]
    fn test_internet_checksum_odd_length() {
        let data = [0x00, 0x01, 0x00];
        let cksum = internet_checksum(&data);
        assert_ne!(cksum, 0); // just verify it doesn't panic
    }

    #[test]
    fn test_parse_ipv4_header() {
        // Minimal IPv4 header: version=4, IHL=5 (20 bytes)
        let mut hdr = vec![0u8; 20];
        hdr[0] = 0x45; // version 4, IHL 5
        hdr[12] = 192;
        hdr[13] = 168;
        hdr[14] = 1;
        hdr[15] = 1;

        let (hdr_len, src) = parse_ipv4_header(&hdr).unwrap();
        assert_eq!(hdr_len, 20);
        assert_eq!(src, Ipv4Addr::new(192, 168, 1, 1));
    }

    #[test]
    fn test_parse_ipv4_header_with_options() {
        // IHL=6 (24 bytes, includes 4 bytes of options)
        let mut hdr = vec![0u8; 24];
        hdr[0] = 0x46; // version 4, IHL 6
        hdr[12] = 10;
        hdr[13] = 0;
        hdr[14] = 0;
        hdr[15] = 1;

        let (hdr_len, src) = parse_ipv4_header(&hdr).unwrap();
        assert_eq!(hdr_len, 24);
        assert_eq!(src, Ipv4Addr::new(10, 0, 0, 1));
    }

    #[test]
    fn test_parse_ipv4_header_too_short() {
        assert!(parse_ipv4_header(&[0x45; 10]).is_none());
    }

    #[test]
    fn test_ipv4_payload() {
        let mut pkt = vec![0u8; 24];
        pkt[0] = 0x45; // IHL 5 = 20 bytes header
        pkt[20] = 0x08; // payload starts here (ICMP echo request type)

        let payload = ipv4_payload(&pkt).unwrap();
        assert_eq!(payload.len(), 4);
        assert_eq!(payload[0], 0x08);
    }

    #[test]
    fn test_parse_icmp_header() {
        let data = [ICMP_TIME_EXCEEDED, 0x00, 0x00, 0x00];
        let hdr = parse_icmp_header(&data).unwrap();
        assert_eq!(hdr.icmp_type, ICMP_TIME_EXCEEDED);
        assert_eq!(hdr.icmp_code, 0);
    }

    #[test]
    fn test_parse_echo_reply() {
        let mut data = vec![0u8; 8];
        data[0] = ICMP_ECHO_REPLY;
        data[4..6].copy_from_slice(&0x1234u16.to_be_bytes());
        data[6..8].copy_from_slice(&0x0005u16.to_be_bytes());

        let (id, seq) = parse_echo_reply(&data).unwrap();
        assert_eq!(id, 0x1234);
        assert_eq!(seq, 0x0005);
    }

    #[test]
    fn test_parse_echo_reply_too_short() {
        assert!(parse_echo_reply(&[0; 4]).is_none());
    }
}
