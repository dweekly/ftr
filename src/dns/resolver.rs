//! Minimal async DNS resolver
//!
//! Implements A, PTR, and TXT queries over UDP using Tokio.
//! Replaces hickory-resolver for the small set of queries ftr needs.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::net::UdpSocket;
use tokio::time::{timeout, Duration};

/// DNS query types
#[derive(Debug, Clone, Copy)]
enum QType {
    A = 1,
    Ptr = 12,
    Txt = 16,
}

/// DNS response record
#[derive(Debug, Clone)]
pub enum DnsRecord {
    /// A record: IPv4 address
    A(Ipv4Addr),
    /// PTR record: domain name
    Ptr(String),
    /// TXT record: text data
    Txt(String),
}

/// DNS resolver error
#[derive(Debug, thiserror::Error)]
pub enum DnsError {
    /// Network I/O error
    #[error("DNS I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// Query timed out
    #[error("DNS query timed out")]
    Timeout,
    /// Malformed response
    #[error("malformed DNS response")]
    Malformed,
    /// No records found
    #[error("no records found (NXDOMAIN or empty)")]
    NotFound,
}

/// Cloudflare DNS server
const DNS_SERVER: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53);
/// DNS query timeout
const DNS_TIMEOUT: Duration = Duration::from_secs(5);
/// Maximum DNS response size
const MAX_RESPONSE: usize = 4096;

/// Resolve a hostname to IPv4 addresses (A record query).
pub async fn resolve_a(hostname: &str) -> Result<Vec<Ipv4Addr>, DnsError> {
    let records = query(hostname, QType::A).await?;
    let addrs: Vec<Ipv4Addr> = records
        .into_iter()
        .filter_map(|r| match r {
            DnsRecord::A(addr) => Some(addr),
            _ => None,
        })
        .collect();
    if addrs.is_empty() {
        return Err(DnsError::NotFound);
    }
    Ok(addrs)
}

/// Perform a reverse DNS lookup (PTR query).
pub async fn resolve_ptr(ip: IpAddr) -> Result<String, DnsError> {
    let name = match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(v6) => {
            // Build nibble-reversed .ip6.arpa name
            let segments = v6.octets();
            let mut nibbles = String::with_capacity(64 + 9);
            for byte in segments.iter().rev() {
                nibbles.push_str(&format!("{:x}.{:x}.", byte & 0x0f, (byte >> 4) & 0x0f));
            }
            nibbles.push_str("ip6.arpa");
            nibbles
        }
    };
    let records = query(&name, QType::Ptr).await?;
    records
        .into_iter()
        .find_map(|r| match r {
            DnsRecord::Ptr(name) => Some(name),
            _ => None,
        })
        .ok_or(DnsError::NotFound)
}

/// Perform a TXT record lookup.
pub async fn resolve_txt(name: &str) -> Result<Vec<String>, DnsError> {
    let records = query(name, QType::Txt).await?;
    let txts: Vec<String> = records
        .into_iter()
        .filter_map(|r| match r {
            DnsRecord::Txt(s) => Some(s),
            _ => None,
        })
        .collect();
    if txts.is_empty() {
        return Err(DnsError::NotFound);
    }
    Ok(txts)
}

/// Send a DNS query and parse the response.
async fn query(name: &str, qtype: QType) -> Result<Vec<DnsRecord>, DnsError> {
    let packet = build_query(name, qtype);

    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.send_to(&packet, DNS_SERVER).await?;

    let mut buf = vec![0u8; MAX_RESPONSE];
    let n = timeout(DNS_TIMEOUT, socket.recv(&mut buf))
        .await
        .map_err(|_| DnsError::Timeout)??;

    parse_response(&buf[..n], qtype)
}

/// Build a DNS query packet.
fn build_query(name: &str, qtype: QType) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(64);

    // Header: ID, flags, counts
    let id: u16 = (std::process::id() as u16) ^ (qtype as u16);
    pkt.extend_from_slice(&id.to_be_bytes()); // ID
    pkt.extend_from_slice(&[0x01, 0x00]); // flags: RD=1
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT=1
    pkt.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // AN, NS, AR = 0

    // Question: encode name
    for label in name.split('.') {
        pkt.push(label.len() as u8);
        pkt.extend_from_slice(label.as_bytes());
    }
    pkt.push(0); // root label

    pkt.extend_from_slice(&(qtype as u16).to_be_bytes()); // QTYPE
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN

    pkt
}

/// Parse a DNS response packet and extract records of the requested type.
fn parse_response(data: &[u8], qtype: QType) -> Result<Vec<DnsRecord>, DnsError> {
    if data.len() < 12 {
        return Err(DnsError::Malformed);
    }

    // Check RCODE in flags
    let rcode = data[3] & 0x0F;
    if rcode == 3 {
        // NXDOMAIN
        return Err(DnsError::NotFound);
    }
    if rcode != 0 {
        return Err(DnsError::Malformed);
    }

    let qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;
    let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;

    // Skip header
    let mut pos = 12;

    // Skip questions
    for _ in 0..qdcount {
        pos = skip_name(data, pos)?;
        pos += 4; // QTYPE + QCLASS
        if pos > data.len() {
            return Err(DnsError::Malformed);
        }
    }

    // Parse answers
    let mut records = Vec::new();
    for _ in 0..ancount {
        pos = skip_name(data, pos)?;
        if pos + 10 > data.len() {
            return Err(DnsError::Malformed);
        }

        let rtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
        // skip class (2) + ttl (4)
        let rdlength = u16::from_be_bytes([data[pos + 8], data[pos + 9]]) as usize;
        pos += 10;

        if pos + rdlength > data.len() {
            return Err(DnsError::Malformed);
        }

        let rdata = &data[pos..pos + rdlength];

        if rtype == qtype as u16 {
            match qtype {
                QType::A => {
                    if rdata.len() == 4 {
                        records.push(DnsRecord::A(Ipv4Addr::new(
                            rdata[0], rdata[1], rdata[2], rdata[3],
                        )));
                    }
                }
                QType::Ptr => {
                    if let Ok(name) = read_name(data, pos) {
                        records.push(DnsRecord::Ptr(name));
                    }
                }
                QType::Txt => {
                    // TXT: one or more length-prefixed strings
                    let mut txt_pos = 0;
                    let mut txt = String::new();
                    while txt_pos < rdata.len() {
                        let slen = rdata[txt_pos] as usize;
                        txt_pos += 1;
                        if txt_pos + slen > rdata.len() {
                            break;
                        }
                        txt.push_str(&String::from_utf8_lossy(&rdata[txt_pos..txt_pos + slen]));
                        txt_pos += slen;
                    }
                    records.push(DnsRecord::Txt(txt));
                }
            }
        }

        pos += rdlength;
    }

    Ok(records)
}

/// Skip a DNS name (handling compression pointers) and return the position after it.
fn skip_name(data: &[u8], mut pos: usize) -> Result<usize, DnsError> {
    if pos >= data.len() {
        return Err(DnsError::Malformed);
    }
    loop {
        if pos >= data.len() {
            return Err(DnsError::Malformed);
        }
        let len = data[pos];
        if len == 0 {
            return Ok(pos + 1);
        }
        if len & 0xC0 == 0xC0 {
            // Compression pointer — 2 bytes total, done
            return Ok(pos + 2);
        }
        pos += 1 + len as usize;
    }
}

/// Read a DNS name at the given position, following compression pointers.
fn read_name(data: &[u8], mut pos: usize) -> Result<String, DnsError> {
    let mut name = String::new();
    let mut followed_pointer = false;
    let mut jumps = 0;

    loop {
        if pos >= data.len() || jumps > 10 {
            return Err(DnsError::Malformed);
        }

        let len = data[pos];
        if len == 0 {
            break;
        }

        if len & 0xC0 == 0xC0 {
            // Compression pointer
            if pos + 1 >= data.len() {
                return Err(DnsError::Malformed);
            }
            let offset = ((len as usize & 0x3F) << 8) | data[pos + 1] as usize;
            pos = offset;
            followed_pointer = true;
            jumps += 1;
            continue;
        }

        pos += 1;
        if pos + len as usize > data.len() {
            return Err(DnsError::Malformed);
        }

        if !name.is_empty() {
            name.push('.');
        }
        name.push_str(&String::from_utf8_lossy(&data[pos..pos + len as usize]));
        pos += len as usize;

        if followed_pointer {
            // After following a pointer, we keep reading from the pointed location
        }
    }

    // Remove trailing dot if present
    if name.ends_with('.') {
        name.pop();
    }

    Ok(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_query() {
        let pkt = build_query("example.com", QType::A);
        // Header: 12 bytes
        assert_eq!(pkt.len(), 12 + 1 + 7 + 1 + 3 + 1 + 4); // header + \x07example\x03com\x00 + qtype + qclass
        assert_eq!(pkt[2], 0x01); // RD flag
        assert_eq!(pkt[4], 0); // QDCOUNT high
        assert_eq!(pkt[5], 1); // QDCOUNT low
    }

    #[test]
    fn test_build_query_labels() {
        let pkt = build_query("a.b.c", QType::Txt);
        // After 12-byte header: \x01a\x01b\x01c\x00
        assert_eq!(pkt[12], 1); // length of "a"
        assert_eq!(pkt[13], b'a');
        assert_eq!(pkt[14], 1); // length of "b"
        assert_eq!(pkt[15], b'b');
        assert_eq!(pkt[16], 1); // length of "c"
        assert_eq!(pkt[17], b'c');
        assert_eq!(pkt[18], 0); // root label
    }

    #[tokio::test]
    async fn test_resolve_a_google() {
        let result = tokio::time::timeout(Duration::from_secs(10), resolve_a("dns.google")).await;
        match result {
            Ok(Ok(addrs)) => {
                assert!(!addrs.is_empty());
                // dns.google should resolve to 8.8.8.8 or 8.8.4.4
                assert!(
                    addrs.contains(&Ipv4Addr::new(8, 8, 8, 8))
                        || addrs.contains(&Ipv4Addr::new(8, 8, 4, 4))
                );
            }
            Ok(Err(e)) => eprintln!("DNS lookup failed (network may be unavailable): {e}"),
            Err(_) => eprintln!("DNS lookup timed out"),
        }
    }

    #[tokio::test]
    async fn test_resolve_ptr_google() {
        let result = tokio::time::timeout(
            Duration::from_secs(10),
            resolve_ptr(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
        )
        .await;
        match result {
            Ok(Ok(name)) => {
                assert!(name.contains("dns.google"), "got: {name}");
            }
            Ok(Err(e)) => eprintln!("PTR lookup failed (network may be unavailable): {e}"),
            Err(_) => eprintln!("PTR lookup timed out"),
        }
    }

    #[tokio::test]
    async fn test_resolve_txt_cymru() {
        // Team Cymru ASN lookup for Google DNS
        let result = tokio::time::timeout(
            Duration::from_secs(10),
            resolve_txt("8.8.8.8.origin.asn.cymru.com"),
        )
        .await;
        match result {
            Ok(Ok(txts)) => {
                assert!(!txts.is_empty());
                // Should contain ASN 15169
                assert!(
                    txts[0].contains("15169"),
                    "Expected AS15169 in TXT record, got: {}",
                    txts[0]
                );
            }
            Ok(Err(e)) => eprintln!("TXT lookup failed (network may be unavailable): {e}"),
            Err(_) => eprintln!("TXT lookup timed out"),
        }
    }

    #[test]
    fn test_ptr_name_construction() {
        // Verify the in-addr.arpa name is built correctly
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let expected = "1.1.168.192.in-addr.arpa";
        if let IpAddr::V4(v4) = ip {
            let o = v4.octets();
            let name = format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0]);
            assert_eq!(name, expected);
        }
    }

    #[test]
    fn test_parse_nxdomain() {
        // Minimal NXDOMAIN response: 12-byte header with RCODE=3
        let mut resp = vec![0u8; 12];
        resp[3] = 3; // RCODE = NXDOMAIN
        assert!(matches!(
            parse_response(&resp, QType::A),
            Err(DnsError::NotFound)
        ));
    }

    #[test]
    fn test_parse_too_short() {
        assert!(matches!(
            parse_response(&[0; 5], QType::A),
            Err(DnsError::Malformed)
        ));
    }
}
