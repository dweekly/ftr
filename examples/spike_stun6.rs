//! Spike: public IPv6 discovery via STUN over UDPv6.
//!
//! ftr currently detects the public IPv4 address with a STUN Binding
//! Request. This spike validates the IPv6 path end to end:
//!
//! 1. Resolve v6-capable STUN servers (stun.l.google.com:19302 via AAAA,
//!    stun.cloudflare.com:3478) and send a Binding Request over UDPv6.
//! 2. Parse XOR-MAPPED-ADDRESS with family 0x02 (IPv6): un-XOR the port
//!    against the top 16 bits of the magic cookie and the 16 address bytes
//!    against magic cookie || transaction ID (RFC 5389 section 15.2).
//! 3. Print the recovered public IPv6 for comparison against
//!    `curl -6 -s https://api64.ipify.org`.
//!
//! Run: `cargo run --example spike_stun6`
//!
//! Findings are recorded in docs/IPV6_DESIGN.md. This spike stays in-repo as
//! a permanent diagnostic: re-run it if STUN/IPv6 behavior is in question.

use std::net::{Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::Duration;

/// STUN magic cookie (RFC 5389 section 6).
const MAGIC_COOKIE: u32 = 0x2112_A442;
/// STUN Binding Request message type (RFC 5389 section 6).
const BINDING_REQUEST: u16 = 0x0001;
/// STUN Binding Success Response message type.
const BINDING_SUCCESS: u16 = 0x0101;
/// XOR-MAPPED-ADDRESS attribute (RFC 5389 section 15.2).
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
/// Address family value for IPv6 in STUN attributes (RFC 5389 section 15.1).
const FAMILY_IPV6: u8 = 0x02;
/// Per-server response wait; STUN servers answer in one RTT.
const RECV_TIMEOUT: Duration = Duration::from_secs(3);

/// Build a STUN Binding Request with the given 12-byte transaction ID.
fn build_binding_request(txid: &[u8; 12]) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(20);
    pkt.extend_from_slice(&BINDING_REQUEST.to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes()); // message length: no attributes
    pkt.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    pkt.extend_from_slice(txid);
    pkt
}

/// Parse a Binding Success Response and extract the XOR-MAPPED-ADDRESS
/// (IPv6 family only). Returns (address, port).
fn parse_response(data: &[u8], txid: &[u8; 12]) -> Result<(Ipv6Addr, u16), String> {
    if data.len() < 20 {
        return Err(format!("response too short: {} bytes", data.len()));
    }
    let msg_type = u16::from_be_bytes([data[0], data[1]]);
    if msg_type != BINDING_SUCCESS {
        return Err(format!("unexpected message type 0x{msg_type:04x}"));
    }
    if data[8..20] != txid[..] {
        return Err("transaction ID mismatch".into());
    }
    let msg_len = u16::from_be_bytes([data[2], data[3]]) as usize;
    let attrs = data
        .get(20..20 + msg_len)
        .ok_or("attribute region exceeds datagram")?;

    let mut pos = 0;
    while pos + 4 <= attrs.len() {
        let attr_type = u16::from_be_bytes([attrs[pos], attrs[pos + 1]]);
        let attr_len = u16::from_be_bytes([attrs[pos + 2], attrs[pos + 3]]) as usize;
        let value = attrs
            .get(pos + 4..pos + 4 + attr_len)
            .ok_or("attribute value exceeds region")?;
        if attr_type == ATTR_XOR_MAPPED_ADDRESS {
            if value.len() < 4 {
                return Err("XOR-MAPPED-ADDRESS too short".into());
            }
            let family = value[1];
            if family != FAMILY_IPV6 {
                return Err(format!(
                    "XOR-MAPPED-ADDRESS family 0x{family:02x}, not IPv6"
                ));
            }
            if value.len() < 20 {
                return Err("IPv6 XOR-MAPPED-ADDRESS needs 20 bytes".into());
            }
            // Port is XORed with the most significant 16 bits of the magic
            // cookie (RFC 5389 section 15.2).
            let xport = u16::from_be_bytes([value[2], value[3]]);
            let port = xport ^ (MAGIC_COOKIE >> 16) as u16;
            // Address bytes are XORed with magic cookie || transaction ID.
            let mut key = [0u8; 16];
            key[..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
            key[4..].copy_from_slice(txid);
            let mut addr = [0u8; 16];
            for (i, b) in addr.iter_mut().enumerate() {
                *b = value[4 + i] ^ key[i];
            }
            return Ok((Ipv6Addr::from(addr), port));
        }
        // Attributes are padded to 4-byte boundaries (RFC 5389 section 15).
        pos += 4 + attr_len.div_ceil(4) * 4;
    }
    Err("no IPv6 XOR-MAPPED-ADDRESS attribute found".into())
}

/// Query one STUN server over UDPv6; returns the mapped (address, port).
fn query(server: &str) -> Result<(Ipv6Addr, u16), String> {
    let v6_addrs: Vec<SocketAddr> = server
        .to_socket_addrs()
        .map_err(|e| format!("resolve failed: {e}"))?
        .filter(SocketAddr::is_ipv6)
        .collect();
    let dest = v6_addrs.first().ok_or("no AAAA record / v6 address")?;
    println!("    resolved to {dest}");

    let socket = UdpSocket::bind("[::]:0").map_err(|e| format!("bind failed: {e}"))?;
    socket
        .set_read_timeout(Some(RECV_TIMEOUT))
        .map_err(|e| format!("timeout: {e}"))?;

    let mut txid = [0u8; 12];
    getrandom::fill(&mut txid).map_err(|e| format!("getrandom: {e}"))?;
    socket
        .send_to(&build_binding_request(&txid), dest)
        .map_err(|e| format!("send failed: {e}"))?;

    let mut buf = [0u8; 1024];
    let (n, from) = socket
        .recv_from(&mut buf)
        .map_err(|e| format!("recv failed (timeout?): {e}"))?;
    println!("    received {n} bytes from {from}");
    parse_response(&buf[..n], &txid)
}

fn main() {
    println!("=== spike_stun6: STUN over UDPv6, XOR-MAPPED-ADDRESS family 0x02 ===");
    let mut results = Vec::new();
    for server in ["stun.l.google.com:19302", "stun.cloudflare.com:3478"] {
        println!("\n[{server}]");
        match query(server) {
            Ok((addr, port)) => {
                println!("    public IPv6: {addr} (mapped port {port})");
                results.push(addr);
            }
            Err(e) => println!("    FAILED: {e}"),
        }
    }
    match results.as_slice() {
        [] => println!("\nVERDICT: no server returned a v6 mapping"),
        [first, rest @ ..] => {
            let consistent = rest.iter().all(|a| a == first);
            println!(
                "\nVERDICT: public IPv6 = {first} (servers consistent: {consistent})\n\
                 Cross-check: curl -6 -s https://api64.ipify.org"
            );
        }
    }
}
