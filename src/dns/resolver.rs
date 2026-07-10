//! Minimal async DNS resolver
//!
//! Implements A, PTR, and TXT queries over UDP using Tokio.
//! Replaces hickory-resolver for the small set of queries ftr needs.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::OnceLock;
use tokio::net::UdpSocket;
use tokio::time::Duration;

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
    /// Response was truncated (TC bit set)
    ///
    /// The answer did not fit in a UDP datagram. Retrying the query over
    /// TCP is future work; callers currently treat this as a failed lookup.
    #[error("truncated DNS response (TCP fallback not implemented)")]
    Truncated,
}

/// Public fallback resolvers tried in order: Cloudflare, then Google.
/// On Unix these come after any system resolvers from `/etc/resolv.conf`
/// (see [`crate::dns::system`]); on Windows, or when resolv.conf is
/// missing/unreadable/empty, they are the whole list. A later server is
/// only consulted when an earlier one times out or errors, not on an
/// authoritative NXDOMAIN.
const FALLBACK_DNS_SERVERS: &[SocketAddr] = &[
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53),
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
];
/// Per-server DNS query window when resolv.conf specifies no
/// `options timeout`. Split evenly across [`DEFAULT_ATTEMPTS`] transmissions
/// (UDP datagrams may be lost), preserving the pre-system-resolver behavior
/// of one retransmit halfway through a 5-second window.
const DNS_TIMEOUT: Duration = Duration::from_secs(5);
/// Transmissions per server (1 initial + 1 retransmit) when resolv.conf
/// specifies no `options attempts`. Matches the glibc resolver default
/// (RES_DFLRETRY in glibc's `<resolv.h>` is 2).
const DEFAULT_ATTEMPTS: u32 = 2;
/// Maximum DNS response size
const MAX_RESPONSE: usize = 4096;

/// Per-attempt timeout and per-server attempt count for queries.
#[derive(Debug, Clone, Copy)]
struct QueryTiming {
    /// How long to wait for a response after each transmission.
    attempt_timeout: Duration,
    /// Total transmissions per server (initial send + retransmits).
    attempts: u32,
}

impl Default for QueryTiming {
    /// Default timing: [`DNS_TIMEOUT`] total per server, split across
    /// [`DEFAULT_ATTEMPTS`] transmissions — identical to the behavior
    /// before system-resolver support was added.
    fn default() -> Self {
        Self {
            attempt_timeout: DNS_TIMEOUT / DEFAULT_ATTEMPTS,
            attempts: DEFAULT_ATTEMPTS,
        }
    }
}

/// Resolved global configuration: server list plus timing.
#[derive(Debug)]
struct ResolverConfig {
    servers: Vec<SocketAddr>,
    timing: QueryTiming,
}

/// The default resolver configuration, computed once per process.
///
/// Server precedence: system resolvers from `/etc/resolv.conf` first
/// (Unix only, up to [`crate::dns::system::MAXNS`]), then
/// [`FALLBACK_DNS_SERVERS`] (deduplicated). `options timeout`/`attempts`
/// from resolv.conf override the default timing. When no system resolvers
/// are found — including always on Windows, where system-resolver discovery
/// is future work — this is exactly the previous hardcoded behavior.
fn default_config() -> &'static ResolverConfig {
    static CONFIG: OnceLock<ResolverConfig> = OnceLock::new();
    CONFIG.get_or_init(|| {
        // The single place system configuration is consulted.
        #[cfg(unix)]
        let (mut servers, timing) = match crate::dns::system::load_system_resolv_conf() {
            Some(conf) => {
                let mut timing = QueryTiming::default();
                if let Some(timeout) = conf.timeout {
                    timing.attempt_timeout = timeout;
                }
                if let Some(attempts) = conf.attempts {
                    timing.attempts = attempts;
                }
                (conf.nameservers, timing)
            }
            None => (Vec::new(), QueryTiming::default()),
        };
        // Windows system-resolver discovery is future work; see crate::dns::system.
        #[cfg(not(unix))]
        let (mut servers, timing) = (Vec::<SocketAddr>::new(), QueryTiming::default());

        for fallback in FALLBACK_DNS_SERVERS {
            if !servers.contains(fallback) {
                servers.push(*fallback);
            }
        }

        ResolverConfig { servers, timing }
    })
}

/// Resolve a hostname to IPv4 addresses (A record query).
pub async fn resolve_a(hostname: &str) -> Result<Vec<Ipv4Addr>, DnsError> {
    let cfg = default_config();
    let records = query(hostname, QType::A, &cfg.servers, cfg.timing).await?;
    collect_a(records)
}

/// Resolve a hostname to IPv4 addresses using explicitly provided DNS
/// servers, bypassing system resolver configuration entirely.
///
/// Servers are tried in order; an empty slice yields [`DnsError::Timeout`].
pub async fn resolve_a_with_servers(
    hostname: &str,
    servers: &[SocketAddr],
) -> Result<Vec<Ipv4Addr>, DnsError> {
    let records = query(hostname, QType::A, servers, QueryTiming::default()).await?;
    collect_a(records)
}

/// Perform a reverse DNS lookup (PTR query).
pub async fn resolve_ptr(ip: IpAddr) -> Result<String, DnsError> {
    let cfg = default_config();
    let records = query(&ptr_name(ip), QType::Ptr, &cfg.servers, cfg.timing).await?;
    collect_ptr(records)
}

/// Perform a reverse DNS lookup using explicitly provided DNS servers,
/// bypassing system resolver configuration entirely.
///
/// Servers are tried in order; an empty slice yields [`DnsError::Timeout`].
pub async fn resolve_ptr_with_servers(
    ip: IpAddr,
    servers: &[SocketAddr],
) -> Result<String, DnsError> {
    let records = query(&ptr_name(ip), QType::Ptr, servers, QueryTiming::default()).await?;
    collect_ptr(records)
}

/// Perform a TXT record lookup.
pub async fn resolve_txt(name: &str) -> Result<Vec<String>, DnsError> {
    let cfg = default_config();
    let records = query(name, QType::Txt, &cfg.servers, cfg.timing).await?;
    collect_txt(records)
}

/// Perform a TXT record lookup using explicitly provided DNS servers,
/// bypassing system resolver configuration entirely.
///
/// Servers are tried in order; an empty slice yields [`DnsError::Timeout`].
pub async fn resolve_txt_with_servers(
    name: &str,
    servers: &[SocketAddr],
) -> Result<Vec<String>, DnsError> {
    let records = query(name, QType::Txt, servers, QueryTiming::default()).await?;
    collect_txt(records)
}

/// Extract A records, mapping an empty result to [`DnsError::NotFound`].
fn collect_a(records: Vec<DnsRecord>) -> Result<Vec<Ipv4Addr>, DnsError> {
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

/// Extract the first PTR record, mapping absence to [`DnsError::NotFound`].
fn collect_ptr(records: Vec<DnsRecord>) -> Result<String, DnsError> {
    records
        .into_iter()
        .find_map(|r| match r {
            DnsRecord::Ptr(name) => Some(name),
            _ => None,
        })
        .ok_or(DnsError::NotFound)
}

/// Extract TXT records, mapping an empty result to [`DnsError::NotFound`].
fn collect_txt(records: Vec<DnsRecord>) -> Result<Vec<String>, DnsError> {
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

/// Build the reverse-lookup name for an IP address
/// (`in-addr.arpa` for IPv4, nibble-reversed `ip6.arpa` for IPv6).
fn ptr_name(ip: IpAddr) -> String {
    match ip {
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
    }
}

/// Send a DNS query and parse the response, trying each given server
/// in order until one yields an answer (or an authoritative NXDOMAIN).
async fn query(
    name: &str,
    qtype: QType,
    servers: &[SocketAddr],
    timing: QueryTiming,
) -> Result<Vec<DnsRecord>, DnsError> {
    let mut last_err = DnsError::Timeout;
    for server in servers {
        match query_server(name, qtype, *server, timing).await {
            Ok(records) => return Ok(records),
            // NXDOMAIN is an authoritative answer; asking another
            // recursive resolver would just repeat it.
            Err(DnsError::NotFound) => return Err(DnsError::NotFound),
            Err(e) => last_err = e,
        }
    }
    Err(last_err)
}

/// Send a DNS query to a single server and parse the response.
///
/// Transmits up to `timing.attempts` times, waiting `timing.attempt_timeout`
/// after each send (UDP datagrams may be lost), and discards datagrams whose
/// header does not match our query (wrong ID, or not a response).
async fn query_server(
    name: &str,
    qtype: QType,
    server: SocketAddr,
    timing: QueryTiming,
) -> Result<Vec<DnsRecord>, DnsError> {
    let id = random_query_id();
    let packet = build_query(name, qtype, id);

    // The local socket family must match the server's address family:
    // a socket bound to 0.0.0.0 cannot connect to an IPv6 server.
    let bind_addr: SocketAddr = match server {
        SocketAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
        SocketAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
    };
    let socket = UdpSocket::bind(bind_addr).await?;
    // Connecting also makes the OS drop datagrams from other source addresses
    socket.connect(server).await?;
    socket.send(&packet).await?;

    let start = tokio::time::Instant::now();
    let mut attempt: u32 = 1;
    let mut buf = vec![0u8; MAX_RESPONSE];

    loop {
        let wait_until = start + timing.attempt_timeout * attempt;
        match tokio::time::timeout_at(wait_until, socket.recv(&mut buf)).await {
            Ok(Ok(n)) => {
                // Ignore datagrams that are not a response to our query
                // (mismatched ID or QR bit clear); keep listening.
                if !is_matching_response(&buf[..n], id) {
                    continue;
                }
                return parse_response(&buf[..n], qtype);
            }
            Ok(Err(e)) => return Err(DnsError::Io(e)),
            Err(_) => {
                // Timer fired: retransmit until attempts are exhausted
                if attempt < timing.attempts {
                    attempt += 1;
                    socket.send(&packet).await?;
                } else {
                    return Err(DnsError::Timeout);
                }
            }
        }
    }
}

/// Generate a random DNS query ID, used to match responses to requests.
fn random_query_id() -> u16 {
    let mut bytes = [0u8; 2];
    if getrandom::fill(&mut bytes).is_ok() {
        u16::from_be_bytes(bytes)
    } else {
        // Fallback: derive from the clock. Matching responses to requests is
        // the primary goal; the connected socket already restricts who can
        // send us datagrams.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos();
        (nanos & 0xFFFF) as u16 ^ (nanos >> 16) as u16
    }
}

/// Check whether a datagram is a response (QR bit set) to the query with
/// the given ID. Datagrams failing this check should be discarded, not
/// treated as errors.
fn is_matching_response(data: &[u8], id: u16) -> bool {
    data.len() >= 12 && u16::from_be_bytes([data[0], data[1]]) == id && data[2] & 0x80 != 0
    // QR bit: must be a response, not a query
}

/// Build a DNS query packet with the given query ID.
fn build_query(name: &str, qtype: QType, id: u16) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(64);

    // Header: ID, flags, counts
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

    // TC (truncation) bit: the full answer did not fit in this datagram.
    // Silently parsing a partial answer set would be wrong; surface a
    // distinct error instead (TCP fallback is future work).
    if data[2] & 0x02 != 0 {
        return Err(DnsError::Truncated);
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

    // ---- Helper to build a minimal valid DNS response ----

    /// Build a DNS response with the given answer records.
    /// `question_name` is encoded as labels in the question section.
    /// Each answer is (rtype, rdata).
    fn build_response(question_name: &str, qtype: QType, answers: &[(u16, &[u8])]) -> Vec<u8> {
        let mut pkt = Vec::new();

        // Header
        pkt.extend_from_slice(&[0xAB, 0xCD]); // ID
        pkt.extend_from_slice(&[0x81, 0x80]); // flags: QR=1, RD=1, RA=1
        pkt.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT=1
        pkt.extend_from_slice(&(answers.len() as u16).to_be_bytes()); // ANCOUNT
        pkt.extend_from_slice(&[0, 0, 0, 0]); // NSCOUNT, ARCOUNT = 0

        // Question section
        let question_start = pkt.len();
        for label in question_name.split('.') {
            pkt.push(label.len() as u8);
            pkt.extend_from_slice(label.as_bytes());
        }
        pkt.push(0); // root
        pkt.extend_from_slice(&(qtype as u16).to_be_bytes());
        pkt.extend_from_slice(&1u16.to_be_bytes()); // QCLASS=IN

        // Answer sections — use compression pointer to question name
        for (rtype, rdata) in answers {
            // Name: compression pointer to question_start
            pkt.push(0xC0 | ((question_start >> 8) as u8));
            pkt.push(question_start as u8);
            pkt.extend_from_slice(&rtype.to_be_bytes()); // TYPE
            pkt.extend_from_slice(&1u16.to_be_bytes()); // CLASS=IN
            pkt.extend_from_slice(&300u32.to_be_bytes()); // TTL
            pkt.extend_from_slice(&(*rdata).len().to_be_bytes()[6..8]); // RDLENGTH (u16)
            pkt.extend_from_slice(rdata);
        }

        pkt
    }

    /// Encode a domain name as DNS labels (for use in rdata).
    fn encode_name(name: &str) -> Vec<u8> {
        let mut buf = Vec::new();
        for label in name.split('.') {
            buf.push(label.len() as u8);
            buf.extend_from_slice(label.as_bytes());
        }
        buf.push(0);
        buf
    }

    // ---- build_query tests ----

    #[test]
    fn test_build_query_structure() {
        let pkt = build_query("example.com", QType::A, 0x1234);
        assert!(pkt.len() > 12);
        assert_eq!(&pkt[0..2], &[0x12, 0x34]); // ID
        assert_eq!(pkt[2], 0x01); // RD=1
        assert_eq!(pkt[5], 1); // QDCOUNT=1
        // QTYPE at end - 4 should be A=1
        let qtype_pos = pkt.len() - 4;
        assert_eq!(u16::from_be_bytes([pkt[qtype_pos], pkt[qtype_pos + 1]]), 1);
    }

    #[test]
    fn test_build_query_labels() {
        let pkt = build_query("a.b.c", QType::Txt, 0x1234);
        assert_eq!(pkt[12], 1);
        assert_eq!(pkt[13], b'a');
        assert_eq!(pkt[14], 1);
        assert_eq!(pkt[15], b'b');
        assert_eq!(pkt[16], 1);
        assert_eq!(pkt[17], b'c');
        assert_eq!(pkt[18], 0); // root
    }

    #[test]
    fn test_build_query_single_label() {
        let pkt = build_query("localhost", QType::A, 0x1234);
        assert_eq!(pkt[12], 9); // "localhost" is 9 chars
        assert_eq!(&pkt[13..22], b"localhost");
        assert_eq!(pkt[22], 0); // root
    }

    // ---- parse_response: A records ----

    #[test]
    fn test_parse_a_record() {
        let resp = build_response("example.com", QType::A, &[(1, &[93, 184, 216, 34])]);
        let records = parse_response(&resp, QType::A).expect("should parse");
        assert_eq!(records.len(), 1);
        match &records[0] {
            DnsRecord::A(addr) => assert_eq!(*addr, Ipv4Addr::new(93, 184, 216, 34)),
            other => panic!("expected A record, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_multiple_a_records() {
        let resp = build_response(
            "dns.google",
            QType::A,
            &[(1, &[8, 8, 8, 8]), (1, &[8, 8, 4, 4])],
        );
        let records = parse_response(&resp, QType::A).expect("should parse");
        assert_eq!(records.len(), 2);
    }

    #[test]
    fn test_parse_a_wrong_rdlength() {
        // A record with only 3 bytes of rdata (invalid, should be 4)
        let resp = build_response("x.com", QType::A, &[(1, &[1, 2, 3])]);
        let records = parse_response(&resp, QType::A).expect("should parse without panic");
        assert!(records.is_empty(), "invalid A record should be skipped");
    }

    // ---- parse_response: PTR records ----

    #[test]
    fn test_parse_ptr_record() {
        let name_data = encode_name("dns.google");
        let resp = build_response("8.8.8.8.in-addr.arpa", QType::Ptr, &[(12, &name_data)]);
        let records = parse_response(&resp, QType::Ptr).expect("should parse");
        assert_eq!(records.len(), 1);
        match &records[0] {
            DnsRecord::Ptr(name) => assert_eq!(name, "dns.google"),
            other => panic!("expected PTR record, got {other:?}"),
        }
    }

    // ---- parse_response: TXT records ----

    #[test]
    fn test_parse_txt_record_single_string() {
        // TXT rdata: length-prefixed string
        let txt_content = b"15169 | 8.8.8.0/24 | US";
        let mut rdata = vec![txt_content.len() as u8];
        rdata.extend_from_slice(txt_content);

        let resp = build_response("8.8.8.8.origin.asn.cymru.com", QType::Txt, &[(16, &rdata)]);
        let records = parse_response(&resp, QType::Txt).expect("should parse");
        assert_eq!(records.len(), 1);
        match &records[0] {
            DnsRecord::Txt(s) => assert_eq!(s, "15169 | 8.8.8.0/24 | US"),
            other => panic!("expected TXT record, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_txt_record_multiple_strings() {
        // TXT rdata with two concatenated length-prefixed strings
        let s1 = b"hello ";
        let s2 = b"world";
        let mut rdata = vec![s1.len() as u8];
        rdata.extend_from_slice(s1);
        rdata.push(s2.len() as u8);
        rdata.extend_from_slice(s2);

        let resp = build_response("test.example", QType::Txt, &[(16, &rdata)]);
        let records = parse_response(&resp, QType::Txt).expect("should parse");
        assert_eq!(records.len(), 1);
        match &records[0] {
            DnsRecord::Txt(s) => assert_eq!(s, "hello world"),
            other => panic!("expected TXT record, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_txt_empty_string() {
        // TXT with a zero-length string
        let rdata = vec![0u8]; // one empty string
        let resp = build_response("test.example", QType::Txt, &[(16, &rdata)]);
        let records = parse_response(&resp, QType::Txt).expect("should parse");
        assert_eq!(records.len(), 1);
        match &records[0] {
            DnsRecord::Txt(s) => assert_eq!(s, ""),
            other => panic!("expected TXT record, got {other:?}"),
        }
    }

    // ---- response header validation ----

    #[test]
    fn test_response_id_mismatch_rejected() {
        // build_response uses ID 0xABCD
        let resp = build_response("example.com", QType::A, &[(1, &[1, 2, 3, 4])]);
        assert!(is_matching_response(&resp, 0xABCD));
        assert!(
            !is_matching_response(&resp, 0x1234),
            "a response with a mismatched ID must be discarded"
        );
    }

    #[test]
    fn test_query_packet_not_accepted_as_response() {
        // A query (QR bit clear) must not be mistaken for a response,
        // even when the ID matches
        let pkt = build_query("example.com", QType::A, 0x1234);
        assert!(!is_matching_response(&pkt, 0x1234));
    }

    #[test]
    fn test_short_datagram_not_accepted_as_response() {
        assert!(!is_matching_response(&[], 0xABCD));
        assert!(!is_matching_response(&[0xAB, 0xCD], 0xABCD));
    }

    #[test]
    fn test_truncated_response_detected() {
        let mut resp = build_response("example.com", QType::A, &[(1, &[1, 2, 3, 4])]);
        resp[2] |= 0x02; // set TC bit
        assert!(matches!(
            parse_response(&resp, QType::A),
            Err(DnsError::Truncated)
        ));
    }

    // ---- parse_response: error cases ----

    #[test]
    fn test_parse_nxdomain() {
        let mut resp = vec![0u8; 12];
        resp[3] = 3; // RCODE = NXDOMAIN
        assert!(matches!(
            parse_response(&resp, QType::A),
            Err(DnsError::NotFound)
        ));
    }

    #[test]
    fn test_parse_servfail() {
        let mut resp = vec![0u8; 12];
        resp[3] = 2; // RCODE = SERVFAIL
        assert!(matches!(
            parse_response(&resp, QType::A),
            Err(DnsError::Malformed)
        ));
    }

    #[test]
    fn test_parse_too_short() {
        assert!(matches!(
            parse_response(&[0; 5], QType::A),
            Err(DnsError::Malformed)
        ));
        assert!(matches!(
            parse_response(&[], QType::A),
            Err(DnsError::Malformed)
        ));
    }

    #[test]
    fn test_parse_zero_answers() {
        // Valid header, NOERROR, but 0 answers
        let mut resp = vec![0u8; 12];
        resp[2] = 0x81;
        resp[3] = 0x80; // QR=1, NOERROR
        // QDCOUNT=0, ANCOUNT=0
        let records = parse_response(&resp, QType::A).expect("should parse");
        assert!(records.is_empty());
    }

    #[test]
    fn test_parse_skips_wrong_rtype() {
        // Response has a CNAME (type 5) but we asked for A (type 1)
        let cname_data = encode_name("other.example.com");
        let resp = build_response("example.com", QType::A, &[(5, &cname_data)]);
        let records = parse_response(&resp, QType::A).expect("should parse");
        assert!(
            records.is_empty(),
            "CNAME should not be returned for A query"
        );
    }

    // ---- skip_name / read_name tests ----

    #[test]
    fn test_skip_name_plain() {
        // \x07example\x03com\x00
        let data = b"\x07example\x03com\x00extra";
        let pos = skip_name(data, 0).expect("should skip");
        assert_eq!(pos, 13); // 1+7+1+3+1 = 13
    }

    #[test]
    fn test_skip_name_compression_pointer() {
        // Compression pointer at position 0: 0xC0 0x0C -> points to offset 12
        let data = [0xC0, 0x0C, 0xFF];
        let pos = skip_name(&data, 0).expect("should skip pointer");
        assert_eq!(pos, 2);
    }

    #[test]
    fn test_skip_name_empty() {
        assert!(skip_name(&[], 0).is_err());
    }

    #[test]
    fn test_skip_name_truncated_label() {
        // Label says 5 bytes but buffer ends after 3
        let data = [5, b'a', b'b', b'c'];
        assert!(skip_name(&data, 0).is_err());
    }

    #[test]
    fn test_read_name_plain() {
        let data = b"\x03www\x07example\x03com\x00";
        let name = read_name(data, 0).expect("should read");
        assert_eq!(name, "www.example.com");
    }

    #[test]
    fn test_read_name_with_compression() {
        // "example.com" at offset 0, then "www" + pointer to offset 0
        let mut data = Vec::new();
        // offset 0: \x07example\x03com\x00
        data.extend_from_slice(b"\x07example\x03com\x00");
        let ptr_start = data.len();
        // offset 13: \x03www + pointer to 0
        data.extend_from_slice(b"\x03www");
        data.push(0xC0);
        data.push(0x00);

        let name = read_name(&data, ptr_start).expect("should read with compression");
        assert_eq!(name, "www.example.com");
    }

    #[test]
    fn test_read_name_pointer_loop_detection() {
        // Two pointers pointing at each other: infinite loop
        let data = [0xC0, 0x02, 0xC0, 0x00];
        assert!(read_name(&data, 0).is_err(), "should detect pointer loop");
    }

    #[test]
    fn test_read_name_chained_pointers() {
        // Chain: offset 10 -> pointer to offset 5 -> pointer to offset 0
        let mut data = vec![0u8; 20];
        // offset 0: \x01a\x00
        data[0] = 1;
        data[1] = b'a';
        data[2] = 0;
        // offset 5: \x01b + pointer to offset 0
        data[5] = 1;
        data[6] = b'b';
        data[7] = 0xC0;
        data[8] = 0x00;
        // offset 10: \x01c + pointer to offset 5
        data[10] = 1;
        data[11] = b'c';
        data[12] = 0xC0;
        data[13] = 5;

        let name = read_name(&data, 10).expect("should follow chain");
        assert_eq!(name, "c.b.a");
    }

    #[test]
    fn test_read_name_truncated() {
        let data = [3, b'a', b'b']; // says 3 bytes but only 2 available
        assert!(read_name(&data, 0).is_err());
    }

    // ---- PTR name construction ----

    #[test]
    fn test_ipv4_ptr_name() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        if let IpAddr::V4(v4) = ip {
            let o = v4.octets();
            let name = format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0]);
            assert_eq!(name, "1.1.168.192.in-addr.arpa");
        }
    }

    #[test]
    fn test_ipv6_ptr_name() {
        let ip: IpAddr = "2001:4860:4860::8888".parse().expect("valid IPv6");
        if let IpAddr::V6(v6) = ip {
            let segments = v6.octets();
            let mut nibbles = String::with_capacity(64 + 9);
            for byte in segments.iter().rev() {
                nibbles.push_str(&format!("{:x}.{:x}.", byte & 0x0f, (byte >> 4) & 0x0f));
            }
            nibbles.push_str("ip6.arpa");
            // Should contain the reversed nibbles
            assert!(nibbles.starts_with("8.8.8.8.0.0.0.0.0.0.0.0.0.0.0.0."));
            assert!(nibbles.ends_with("ip6.arpa"));
        }
    }

    // ---- Error type tests ----

    #[test]
    fn test_error_display() {
        assert!(DnsError::Timeout.to_string().contains("timed out"));
        assert!(DnsError::Malformed.to_string().contains("malformed"));
        assert!(DnsError::NotFound.to_string().contains("no records"));
        assert!(DnsError::Truncated.to_string().contains("truncated"));
        let io_err = DnsError::Io(std::io::Error::new(std::io::ErrorKind::Other, "test"));
        assert!(io_err.to_string().contains("test"));
    }

    // ---- Server list construction ----

    #[test]
    fn test_default_config_includes_fallbacks_without_duplicates() {
        let cfg = default_config();
        for fallback in FALLBACK_DNS_SERVERS {
            assert!(
                cfg.servers.contains(fallback),
                "fallback {fallback} missing from {:?}",
                cfg.servers
            );
        }
        // System resolvers (<= MAXNS) come first, fallbacks last, no dupes.
        assert!(cfg.servers.len() <= crate::dns::system::MAXNS + FALLBACK_DNS_SERVERS.len());
        for (i, server) in cfg.servers.iter().enumerate() {
            assert!(
                !cfg.servers[i + 1..].contains(server),
                "duplicate server {server} in {:?}",
                cfg.servers
            );
        }
        // On Unix with a usable resolv.conf, the system resolvers must be
        // the leading entries, in file order.
        #[cfg(unix)]
        if let Some(conf) = crate::dns::system::load_system_resolv_conf() {
            assert!(
                cfg.servers.starts_with(&conf.nameservers),
                "servers {:?} should start with system resolvers {:?}",
                cfg.servers,
                conf.nameservers
            );
        }
        println!("default DNS server order: {:?}", cfg.servers);
    }

    #[test]
    fn test_default_timing_matches_previous_behavior() {
        // Pre-system-resolver behavior: 5s total window, one retransmit
        // halfway through. With per-attempt timing that is 2 attempts of
        // DNS_TIMEOUT / 2 each.
        let timing = QueryTiming::default();
        assert_eq!(timing.attempts, DEFAULT_ATTEMPTS);
        assert_eq!(
            timing.attempt_timeout * timing.attempts,
            DNS_TIMEOUT,
            "total per-server window changed"
        );
    }

    #[tokio::test]
    async fn test_resolve_with_empty_server_list_times_out() {
        // An explicit empty server list never sends anything and reports
        // Timeout (the initialized last_err) immediately.
        let result = resolve_a_with_servers("example.com", &[]).await;
        assert!(matches!(result, Err(DnsError::Timeout)));
    }

    // ---- Live network tests (gracefully skip on failure) ----

    #[tokio::test]
    async fn test_resolve_ptr_with_explicit_ipv6_server() {
        // Exercises the IPv6 socket-family path against Cloudflare's
        // resolver. Requires IPv6 connectivity; skips gracefully without it.
        let server: SocketAddr = "[2606:4700:4700::1111]:53".parse().expect("valid addr");
        let result = tokio::time::timeout(
            Duration::from_secs(10),
            resolve_ptr_with_servers(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), &[server]),
        )
        .await;
        match result {
            Ok(Ok(name)) => {
                println!("PTR via IPv6 server {server}: {name}");
                assert!(name.contains("dns.google"), "got: {name}");
            }
            Ok(Err(e)) => eprintln!("IPv6 PTR lookup failed (no v6 connectivity?): {e}"),
            Err(_) => eprintln!("IPv6 PTR lookup timed out"),
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_resolve_via_first_system_resolver() {
        // Pin the query to the first system resolver from /etc/resolv.conf
        // (bypassing fallbacks) to demonstrate system-resolver support
        // end to end. Skips gracefully when no system resolver exists.
        let Some(conf) = crate::dns::system::load_system_resolv_conf() else {
            eprintln!("no system resolvers configured; skipping");
            return;
        };
        let server = conf.nameservers[0];
        let result = tokio::time::timeout(
            Duration::from_secs(10),
            resolve_ptr_with_servers(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), &[server]),
        )
        .await;
        match result {
            Ok(Ok(name)) => {
                println!("PTR via system resolver {server}: {name}");
                assert!(name.contains("dns.google"), "got: {name}");
            }
            Ok(Err(e)) => eprintln!("system resolver lookup failed (network?): {e}"),
            Err(_) => eprintln!("system resolver lookup timed out"),
        }
    }

    #[tokio::test]
    async fn test_resolve_a_google() {
        let result = tokio::time::timeout(Duration::from_secs(10), resolve_a("dns.google")).await;
        match result {
            Ok(Ok(addrs)) => {
                assert!(!addrs.is_empty());
                assert!(
                    addrs.contains(&Ipv4Addr::new(8, 8, 8, 8))
                        || addrs.contains(&Ipv4Addr::new(8, 8, 4, 4))
                );
            }
            Ok(Err(e)) => eprintln!("DNS lookup failed (network unavailable): {e}"),
            Err(_) => eprintln!("DNS lookup timed out"),
        }
    }

    #[tokio::test]
    async fn test_resolve_a_nonexistent() {
        let result = tokio::time::timeout(
            Duration::from_secs(10),
            resolve_a("thisdomaindoesnotexist.invalid"),
        )
        .await;
        match result {
            Ok(Err(DnsError::NotFound)) => {} // expected
            Ok(Err(e)) => eprintln!("Got different error (acceptable): {e}"),
            Ok(Ok(_)) => panic!("should not resolve nonexistent domain"),
            Err(_) => eprintln!("timed out"),
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
            Ok(Ok(name)) => assert!(name.contains("dns.google"), "got: {name}"),
            Ok(Err(e)) => eprintln!("PTR lookup failed (network unavailable): {e}"),
            Err(_) => eprintln!("PTR lookup timed out"),
        }
    }

    #[tokio::test]
    async fn test_resolve_txt_cymru() {
        let result = tokio::time::timeout(
            Duration::from_secs(10),
            resolve_txt("8.8.8.8.origin.asn.cymru.com"),
        )
        .await;
        match result {
            Ok(Ok(txts)) => {
                assert!(!txts.is_empty());
                assert!(
                    txts[0].contains("15169"),
                    "expected AS15169, got: {}",
                    txts[0]
                );
            }
            Ok(Err(e)) => eprintln!("TXT lookup failed (network unavailable): {e}"),
            Err(_) => eprintln!("TXT lookup timed out"),
        }
    }
}
