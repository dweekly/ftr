//! Spike: IPv6 origin ASN lookup via Team Cymru DNS.
//!
//! ftr's v4 ASN lookup queries `<reversed-octets>.origin.asn.cymru.com` TXT.
//! The v6 equivalent nibble-reverses the FULL 32-nibble address and queries
//! `<nibbles>.origin6.asn.cymru.com`
//! (<https://www.team-cymru.com/ip-asn-mapping>).
//!
//! This spike validates:
//! 1. Nibble-reversal of an IPv6 address (2001:4860:4860::8888 must become
//!    the 32-label `8.8.8.8...1.0.0.2` form).
//! 2. A hand-rolled UDP DNS TXT query (same wire format as
//!    src/dns/resolver.rs) against the origin6 zone.
//! 3. Parsing the `AS | prefix | CC | registry | date` TXT payload —
//!    expecting AS15169 (Google) for 2001:4860:4860::8888.
//!
//! Run: `cargo run --example spike_asn6`
//!
//! Findings are recorded in docs/IPV6_DESIGN.md. This spike stays in-repo as
//! a permanent diagnostic: re-run it if the Cymru origin6 zone or DNS
//! behavior is in question.

use std::net::{Ipv6Addr, UdpSocket};
use std::time::Duration;

/// DNS TXT record type (RFC 1035 section 3.2.2).
const QTYPE_TXT: u16 = 16;
/// Cloudflare public resolver, IPv4 transport (same server family as
/// src/dns/resolver.rs uses; the transport family is independent of the
/// record being queried).
const DNS_SERVER: &str = "1.1.1.1:53";
/// Query timeout, matching DNS_TIMEOUT in src/dns/resolver.rs.
const DNS_TIMEOUT: Duration = Duration::from_secs(5);

/// Nibble-reverse an IPv6 address into the Cymru origin6 query name:
/// each of the 32 hex nibbles becomes a label, least significant first.
fn origin6_name(addr: Ipv6Addr) -> String {
    let mut name = String::with_capacity(32 * 2 + "origin6.asn.cymru.com".len());
    for byte in addr.octets().iter().rev() {
        // Low nibble first: it is the less significant of the pair and the
        // whole name runs least-significant-nibble first.
        name.push_str(&format!("{:x}.{:x}.", byte & 0x0f, byte >> 4));
    }
    name.push_str("origin6.asn.cymru.com");
    name
}

/// Build a DNS TXT query packet (wire format mirrors
/// src/dns/resolver.rs::build_query).
fn build_query(name: &str, id: u16) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(name.len() + 18);
    pkt.extend_from_slice(&id.to_be_bytes());
    pkt.extend_from_slice(&[0x01, 0x00]); // flags: RD=1
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    pkt.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // AN/NS/AR = 0
    for label in name.split('.') {
        pkt.push(label.len() as u8);
        pkt.extend_from_slice(label.as_bytes());
    }
    pkt.push(0); // root
    pkt.extend_from_slice(&QTYPE_TXT.to_be_bytes());
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QCLASS=IN
    pkt
}

/// Skip a DNS name (labels or compression pointer); returns position after.
fn skip_name(data: &[u8], mut pos: usize) -> Result<usize, String> {
    loop {
        let len = *data.get(pos).ok_or("truncated name")?;
        if len == 0 {
            return Ok(pos + 1);
        }
        if len & 0xC0 == 0xC0 {
            return Ok(pos + 2);
        }
        pos += 1 + len as usize;
    }
}

/// Extract TXT record strings from a DNS response (parse logic mirrors
/// src/dns/resolver.rs::parse_response, trimmed to TXT only).
fn parse_txt_response(data: &[u8], id: u16) -> Result<Vec<String>, String> {
    if data.len() < 12 {
        return Err("response too short".into());
    }
    if u16::from_be_bytes([data[0], data[1]]) != id {
        return Err("DNS ID mismatch".into());
    }
    let rcode = data[3] & 0x0F;
    if rcode != 0 {
        return Err(format!("DNS RCODE {rcode}"));
    }
    let qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;
    let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;

    let mut pos = 12;
    for _ in 0..qdcount {
        pos = skip_name(data, pos)? + 4;
    }

    let mut txts = Vec::new();
    for _ in 0..ancount {
        pos = skip_name(data, pos)?;
        let header = data.get(pos..pos + 10).ok_or("truncated RR header")?;
        let rtype = u16::from_be_bytes([header[0], header[1]]);
        let rdlength = u16::from_be_bytes([header[8], header[9]]) as usize;
        pos += 10;
        let rdata = data.get(pos..pos + rdlength).ok_or("truncated RDATA")?;
        if rtype == QTYPE_TXT {
            // TXT rdata: sequence of length-prefixed character strings.
            let mut txt = String::new();
            let mut tpos = 0;
            while tpos < rdata.len() {
                let slen = rdata[tpos] as usize;
                tpos += 1;
                let chunk = rdata.get(tpos..tpos + slen).ok_or("truncated TXT string")?;
                txt.push_str(&String::from_utf8_lossy(chunk));
                tpos += slen;
            }
            txts.push(txt);
        }
        pos += rdlength;
    }
    Ok(txts)
}

fn main() -> Result<(), String> {
    println!("=== spike_asn6: Team Cymru origin6 ASN lookup over UDP DNS ===");

    let addr: Ipv6Addr = "2001:4860:4860::8888".parse().expect("valid literal");
    let name = origin6_name(addr);
    println!("\nquery target: {addr}");
    println!("origin6 name: {name}");

    // Sanity-check the nibble reversal deterministically before going to
    // the network: last four labels must be the first hextet reversed.
    if !name.ends_with("1.0.0.2.origin6.asn.cymru.com")
        || !name.starts_with("8.8.8.8.0.0.0.0.0.0.0.0.0.0.0.0.")
    {
        return Err("nibble reversal is wrong".into());
    }
    println!("nibble reversal sanity check: OK");

    // DNS ID: derived from PID like src/dns/resolver.rs, purely to vary
    // between runs; response validation checks it round-trips.
    let id = std::process::id() as u16;
    let socket = UdpSocket::bind("0.0.0.0:0").map_err(|e| format!("bind: {e}"))?;
    socket
        .set_read_timeout(Some(DNS_TIMEOUT))
        .map_err(|e| format!("timeout: {e}"))?;
    socket
        .send_to(&build_query(&name, id), DNS_SERVER)
        .map_err(|e| format!("send: {e}"))?;

    let mut buf = [0u8; 4096];
    let n = socket
        .recv_from(&mut buf)
        .map_err(|e| format!("recv (timeout?): {e}"))?
        .0;
    println!("received {n}-byte DNS response");

    let txts = parse_txt_response(&buf[..n], id)?;
    if txts.is_empty() {
        return Err("no TXT records in answer".into());
    }
    for txt in &txts {
        println!("TXT: \"{txt}\"");
        // Format: "AS | prefix | CC | registry | allocated-date"
        let fields: Vec<&str> = txt.split('|').map(str::trim).collect();
        if let [asn, prefix, cc, registry, date] = fields.as_slice() {
            println!(
                "  parsed: ASN={asn} prefix={prefix} country={cc} \
                 registry={registry} allocated={date}"
            );
            if *asn == "15169" {
                println!("  => AS15169 (Google) as expected — origin6 lookup works");
            } else {
                println!("  => UNEXPECTED ASN (expected 15169)");
            }
        } else {
            println!("  unexpected field count: {}", fields.len());
        }
    }
    Ok(())
}
