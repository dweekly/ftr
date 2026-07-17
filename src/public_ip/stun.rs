//! STUN client for fast public IP detection
//!
//! This module implements a minimal STUN client to quickly determine
//! the public IP address. STUN is much faster than HTTPS because:
//! - Single UDP packet exchange (no TCP handshake)
//! - No TLS negotiation
//! - Minimal protocol overhead
//! - ~RTT latency instead of multiple round trips

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

/// STUN magic cookie (fixed value in all STUN messages)
const STUN_MAGIC_COOKIE: u32 = 0x2112A442;

/// STUN Binding Request message type
const BINDING_REQUEST: u16 = 0x0001;

/// STUN Binding Response message type
const BINDING_SUCCESS_RESPONSE: u16 = 0x0101;

/// STUN XOR-MAPPED-ADDRESS attribute type
const XOR_MAPPED_ADDRESS: u16 = 0x0020;

/// STUN MAPPED-ADDRESS attribute type (legacy)
const MAPPED_ADDRESS: u16 = 0x0001;

/// Well-known public STUN servers
pub const STUN_SERVERS: &[&str] = &[
    "stun.l.google.com:19302",  // Primary Google STUN - most reliable
    "stun1.l.google.com:19302", // Backup
    "stun.cloudflare.com:3478", // Alternative provider
];

/// Error type for STUN operations
///
/// This enum is `#[non_exhaustive]`: new error variants may be added in
/// minor releases, so downstream matches must include a wildcard arm.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StunError {
    /// IO error during STUN communication
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    /// STUN response format was invalid
    #[error("Invalid STUN response")]
    InvalidResponse,

    /// No mapped address found in STUN response
    #[error("No mapped address in response")]
    NoMappedAddress,

    /// Timeout waiting for STUN response
    #[error("Timeout waiting for response")]
    Timeout,
}

/// Get public IP using STUN protocol with injected cache
pub async fn get_public_ip_stun_with_cache(
    server: &str,
    timeout: Duration,
    cache: &Arc<RwLock<crate::public_ip::stun_cache::StunCache>>,
) -> Result<IpAddr, StunError> {
    get_public_ip_stun_with_cache_and_verbose(server, timeout, cache, 0).await
}

/// Address-family filter for STUN queries.
///
/// Crate-internal: the public entry points are
/// [`StunClient::get_public_ip_v4`](crate::public_ip::StunClient::get_public_ip_v4),
/// [`StunClient::get_public_ip_v6`](crate::public_ip::StunClient::get_public_ip_v6),
/// and [`StunClient::get_public_ips`](crate::public_ip::StunClient::get_public_ips).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StunFamily {
    /// Query over IPv4 only (A records / v4 server addresses)
    V4,
    /// Query over IPv6 only (AAAA records / v6 server addresses)
    V6,
}

impl StunFamily {
    /// Whether a resolved server address belongs to this family
    fn matches_server(self, addr: &SocketAddr) -> bool {
        match self {
            StunFamily::V4 => addr.is_ipv4(),
            StunFamily::V6 => addr.is_ipv6(),
        }
    }

    /// Whether a mapped address returned by the server belongs to this family
    fn matches_ip(self, ip: &IpAddr) -> bool {
        match self {
            StunFamily::V4 => ip.is_ipv4(),
            StunFamily::V6 => ip.is_ipv6(),
        }
    }
}

/// Get public IP using STUN protocol with injected cache and an explicit
/// verbosity level (2+ prints per-server diagnostics to stderr)
pub async fn get_public_ip_stun_with_cache_and_verbose(
    server: &str,
    timeout: Duration,
    cache: &Arc<RwLock<crate::public_ip::stun_cache::StunCache>>,
    verbose: u8,
) -> Result<IpAddr, StunError> {
    get_public_ip_stun_filtered(server, timeout, cache, verbose, None).await
}

/// Get public IP from one STUN server, optionally restricted to a single
/// address family. With a family set, only server addresses of that family
/// are contacted and a mapped address of the wrong family is rejected.
async fn get_public_ip_stun_filtered(
    server: &str,
    timeout: Duration,
    cache: &Arc<RwLock<crate::public_ip::stun_cache::StunCache>>,
    verbose: u8,
    family: Option<StunFamily>,
) -> Result<IpAddr, StunError> {
    if verbose >= 2 {
        eprintln!("[STUN] Attempting to contact STUN server: {}", server);
    }

    // Get server addresses from provided cache
    let cache_read = cache.read().await;
    let server_addrs = cache_read
        .get_stun_server_addrs(server)
        .await
        .map_err(|e| {
            if verbose >= 2 {
                eprintln!("[STUN] Failed to resolve {}: {}", server, e);
            }
            StunError::IoError(e)
        })?;
    drop(cache_read);

    // Try each address (of the requested family, if any) until one works
    for server_addr in server_addrs {
        if let Some(family) = family {
            if !family.matches_server(&server_addr) {
                continue;
            }
        }
        if verbose >= 2 {
            eprintln!("[STUN] Trying {} (resolved from {})", server_addr, server);
        }
        match get_public_ip_stun_addr(server_addr, timeout).await {
            Ok(ip) => {
                // Defense in depth: a server contacted over one family
                // should map that family, but reject a mismatch rather
                // than report e.g. a v4 address as the public IPv6.
                if let Some(family) = family {
                    if !family.matches_ip(&ip) {
                        if verbose >= 2 {
                            eprintln!(
                                "[STUN] {} returned {} which is not the requested family; skipping",
                                server_addr, ip
                            );
                        }
                        continue;
                    }
                }
                if verbose >= 2 {
                    eprintln!(
                        "[STUN] Successfully obtained public IP {} from {}",
                        ip, server
                    );
                }
                return Ok(ip);
            }
            Err(e) => {
                if verbose >= 2 {
                    eprintln!("[STUN] Failed to get IP from {}: {:?}", server_addr, e);
                }
                continue; // Try next address
            }
        }
    }

    if verbose >= 2 {
        eprintln!("[STUN] All addresses for {} failed", server);
    }
    Err(StunError::Timeout)
}

/// Get public IP using STUN protocol with a specific server address
async fn get_public_ip_stun_addr(
    server_addr: SocketAddr,
    timeout: Duration,
) -> Result<IpAddr, StunError> {
    // Use tokio's async UDP socket, bound to the same address family as
    // the server (a v4-bound socket cannot send to a v6 server and vice
    // versa).
    let bind_addr = if server_addr.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let socket = tokio::net::UdpSocket::bind(bind_addr).await?;

    // Build STUN Binding Request
    let request = build_binding_request();

    // Send request
    socket.send_to(&request, server_addr).await?;

    // Receive response with timeout
    let mut buf = vec![0u8; 1024];
    let result = tokio::time::timeout(timeout, socket.recv_from(&mut buf)).await;

    let (size, _) = match result {
        Ok(Ok(data)) => data,
        Ok(Err(e)) => return Err(StunError::IoError(e)),
        Err(_) => return Err(StunError::Timeout),
    };

    // Parse response
    parse_stun_response(&buf[..size])
}

/// Get public IP using STUN with fallback to the default servers (with injected cache)
///
/// Tries each server in [`STUN_SERVERS`] in order. To use a custom server
/// list, see [`get_public_ip_stun_with_servers_and_cache`].
pub async fn get_public_ip_stun_with_fallback_and_cache(
    timeout: Duration,
    cache: &Arc<RwLock<crate::public_ip::stun_cache::StunCache>>,
) -> Result<IpAddr, StunError> {
    let servers: Vec<String> = STUN_SERVERS.iter().map(|s| (*s).to_string()).collect();
    get_public_ip_stun_with_servers_and_cache(&servers, timeout, cache, 0).await
}

/// Get public IP using STUN, trying the provided servers in order (with injected cache)
///
/// The first server is the primary; the remaining servers are fallbacks
/// tried only if earlier ones fail. Server addresses are resolved through
/// (and cached in) the provided cache on demand. `verbose` levels 2+
/// print per-server diagnostics to stderr.
pub async fn get_public_ip_stun_with_servers_and_cache(
    servers: &[String],
    timeout: Duration,
    cache: &Arc<RwLock<crate::public_ip::stun_cache::StunCache>>,
    verbose: u8,
) -> Result<IpAddr, StunError> {
    for server in servers {
        match get_public_ip_stun_with_cache_and_verbose(server, timeout, cache, verbose).await {
            Ok(ip) => return Ok(ip),
            Err(_) => continue, // Try next server
        }
    }
    Err(StunError::Timeout)
}

/// Get the public IP for one address family using STUN, trying the provided
/// servers in order (with injected cache).
///
/// Like [`get_public_ip_stun_with_servers_and_cache`] but restricted to a
/// single address family: only server addresses of that family are
/// contacted (e.g. AAAA-resolved addresses for [`StunFamily::V6`]), so the
/// mapped address the server reports is the public address for that family.
pub(crate) async fn get_public_ip_stun_family_with_servers_and_cache(
    servers: &[String],
    timeout: Duration,
    cache: &Arc<RwLock<crate::public_ip::stun_cache::StunCache>>,
    verbose: u8,
    family: StunFamily,
) -> Result<IpAddr, StunError> {
    for server in servers {
        match get_public_ip_stun_filtered(server, timeout, cache, verbose, Some(family)).await {
            Ok(ip) => return Ok(ip),
            Err(_) => continue, // Try next server
        }
    }
    Err(StunError::Timeout)
}

/// Build a STUN Binding Request message
fn build_binding_request() -> Vec<u8> {
    let mut request = Vec::with_capacity(20);

    // Message Type (2 bytes) - Binding Request
    request.extend_from_slice(&BINDING_REQUEST.to_be_bytes());

    // Message Length (2 bytes) - 0 for empty request
    request.extend_from_slice(&0u16.to_be_bytes());

    // Magic Cookie (4 bytes)
    request.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());

    // Transaction ID (12 bytes) - random
    let mut transaction_id = [0u8; 12];
    getrandom::fill(&mut transaction_id).unwrap_or_else(|_| {
        // Fallback to timestamp-based ID if random fails
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let nanos = now.as_nanos() as u64;
        transaction_id[..8].copy_from_slice(&nanos.to_be_bytes());
    });
    request.extend_from_slice(&transaction_id);

    request
}

/// Parse a STUN response and extract the mapped address
fn parse_stun_response(data: &[u8]) -> Result<IpAddr, StunError> {
    if data.len() < 20 {
        return Err(StunError::InvalidResponse);
    }

    // Check message type (should be Binding Success Response)
    let msg_type = u16::from_be_bytes([data[0], data[1]]);
    if msg_type != BINDING_SUCCESS_RESPONSE {
        return Err(StunError::InvalidResponse);
    }

    // Check magic cookie
    let magic = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    if magic != STUN_MAGIC_COOKIE {
        return Err(StunError::InvalidResponse);
    }

    // Transaction ID (bytes 8..20 of the header): the response echoes the
    // request's transaction ID, and RFC 5389 section 15.2 XORs the IPv6
    // mapped-address bytes against magic cookie || transaction ID.
    let transaction_id: [u8; 12] = data[8..20]
        .try_into()
        .expect("slice of a >=20-byte buffer is 12 bytes");

    // Parse attributes
    let msg_length = u16::from_be_bytes([data[2], data[3]]) as usize;
    let mut offset = 20; // Skip header

    while offset + 4 <= 20 + msg_length && offset + 4 <= data.len() {
        let attr_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let attr_length = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;

        if offset + 4 + attr_length > data.len() {
            break;
        }

        match attr_type {
            XOR_MAPPED_ADDRESS if attr_length >= 8 => {
                return parse_xor_mapped_address(
                    &data[offset + 4..offset + 4 + attr_length],
                    &transaction_id,
                );
            }
            MAPPED_ADDRESS if attr_length >= 8 => {
                // Legacy MAPPED-ADDRESS
                return parse_mapped_address(&data[offset + 4..offset + 4 + attr_length]);
            }
            _ => {}
        }

        // Move to next attribute (with padding to 4-byte boundary)
        offset += 4 + ((attr_length + 3) & !3);
    }

    Err(StunError::NoMappedAddress)
}

/// Parse XOR-MAPPED-ADDRESS attribute (RFC 5389 section 15.2)
///
/// The port is XORed with the most significant 16 bits of the magic
/// cookie. IPv4 address bytes are XORed with the magic cookie; IPv6
/// address bytes are XORed with the concatenation of the magic cookie and
/// the transaction ID. Validated against live Google and Cloudflare STUN
/// servers by `examples/spike_stun6.rs`.
fn parse_xor_mapped_address(data: &[u8], transaction_id: &[u8; 12]) -> Result<IpAddr, StunError> {
    if data.len() < 8 {
        return Err(StunError::InvalidResponse);
    }

    let family = data[1];
    let _port = u16::from_be_bytes([data[2], data[3]]) ^ (STUN_MAGIC_COOKIE >> 16) as u16;

    match family {
        0x01 => {
            // IPv4: 4 address bytes XORed with the magic cookie
            if data.len() < 8 {
                return Err(StunError::InvalidResponse);
            }
            let addr_bytes = [
                data[4] ^ (STUN_MAGIC_COOKIE >> 24) as u8,
                data[5] ^ (STUN_MAGIC_COOKIE >> 16) as u8,
                data[6] ^ (STUN_MAGIC_COOKIE >> 8) as u8,
                data[7] ^ STUN_MAGIC_COOKIE as u8,
            ];
            Ok(IpAddr::V4(std::net::Ipv4Addr::from(addr_bytes)))
        }
        0x02 => {
            // IPv6: 16 address bytes XORed with magic cookie || transaction ID
            if data.len() < 20 {
                return Err(StunError::InvalidResponse);
            }
            let mut key = [0u8; 16];
            key[..4].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
            key[4..].copy_from_slice(transaction_id);
            let mut addr_bytes = [0u8; 16];
            for (i, byte) in addr_bytes.iter_mut().enumerate() {
                *byte = data[4 + i] ^ key[i];
            }
            Ok(IpAddr::V6(std::net::Ipv6Addr::from(addr_bytes)))
        }
        _ => Err(StunError::InvalidResponse),
    }
}

/// Parse legacy MAPPED-ADDRESS attribute (RFC 5389 section 15.1, no XOR)
fn parse_mapped_address(data: &[u8]) -> Result<IpAddr, StunError> {
    if data.len() < 8 {
        return Err(StunError::InvalidResponse);
    }

    let family = data[1];

    match family {
        0x01 => {
            // IPv4
            let addr_bytes = [data[4], data[5], data[6], data[7]];
            Ok(IpAddr::V4(std::net::Ipv4Addr::from(addr_bytes)))
        }
        0x02 => {
            // IPv6: 16 plain (non-XORed) address bytes
            if data.len() < 20 {
                return Err(StunError::InvalidResponse);
            }
            let addr_bytes: [u8; 16] = data[4..20]
                .try_into()
                .expect("length checked above: 16 bytes");
            Ok(IpAddr::V6(std::net::Ipv6Addr::from(addr_bytes)))
        }
        _ => Err(StunError::InvalidResponse),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_binding_request() {
        let request = build_binding_request();
        assert_eq!(request.len(), 20);

        // Check message type
        assert_eq!(
            u16::from_be_bytes([request[0], request[1]]),
            BINDING_REQUEST
        );

        // Check magic cookie
        assert_eq!(
            u32::from_be_bytes([request[4], request[5], request[6], request[7]]),
            STUN_MAGIC_COOKIE
        );
    }

    /// Build a synthetic Binding Success Response containing one attribute.
    fn synthetic_response(transaction_id: &[u8; 12], attr_type: u16, attr_value: &[u8]) -> Vec<u8> {
        let padded_len = attr_value.len().div_ceil(4) * 4;
        let mut resp = Vec::new();
        resp.extend_from_slice(&BINDING_SUCCESS_RESPONSE.to_be_bytes());
        resp.extend_from_slice(&((4 + padded_len) as u16).to_be_bytes());
        resp.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        resp.extend_from_slice(transaction_id);
        resp.extend_from_slice(&attr_type.to_be_bytes());
        resp.extend_from_slice(&(attr_value.len() as u16).to_be_bytes());
        resp.extend_from_slice(attr_value);
        resp.resize(resp.len() + padded_len - attr_value.len(), 0);
        resp
    }

    #[test]
    fn test_parse_xor_mapped_address_v6_synthetic() {
        // Known transaction ID and known address; the XOR key is
        // magic cookie || transaction ID (RFC 5389 section 15.2).
        let transaction_id: [u8; 12] = [
            0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18, 0x29, 0x3a, 0x4b, 0x5c,
        ];
        let addr: std::net::Ipv6Addr = "2001:5a8:4684:c00:41b1:1c86:aee8:e97"
            .parse()
            .expect("valid IPv6 literal");
        let port: u16 = 52410;

        let mut key = [0u8; 16];
        key[..4].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        key[4..].copy_from_slice(&transaction_id);

        // XOR-MAPPED-ADDRESS value: reserved, family, x-port, x-address
        let mut value = vec![0u8, 0x02];
        value.extend_from_slice(&(port ^ (STUN_MAGIC_COOKIE >> 16) as u16).to_be_bytes());
        for (i, byte) in addr.octets().iter().enumerate() {
            value.push(byte ^ key[i]);
        }

        let resp = synthetic_response(&transaction_id, XOR_MAPPED_ADDRESS, &value);
        let parsed = parse_stun_response(&resp).expect("synthetic v6 response must parse");
        assert_eq!(parsed, IpAddr::V6(addr));
    }

    #[test]
    fn test_parse_xor_mapped_address_v6_wrong_transaction_id_garbles_address() {
        // The un-XOR depends on the transaction ID: the same attribute
        // bytes under a different transaction ID must NOT yield the
        // original address (guards against ignoring the transaction ID).
        let txid_a: [u8; 12] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let txid_b: [u8; 12] = [12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1];
        let addr: std::net::Ipv6Addr = "2001:4860:4860::8888".parse().expect("valid literal");

        let mut key = [0u8; 16];
        key[..4].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        key[4..].copy_from_slice(&txid_a);
        let mut value = vec![0u8, 0x02, 0, 0];
        for (i, byte) in addr.octets().iter().enumerate() {
            value.push(byte ^ key[i]);
        }

        let resp = synthetic_response(&txid_b, XOR_MAPPED_ADDRESS, &value);
        let parsed = parse_stun_response(&resp).expect("still parses structurally");
        assert_ne!(parsed, IpAddr::V6(addr));
    }

    #[test]
    fn test_parse_xor_mapped_address_v6_truncated() {
        // Family 0x02 with only a v4-sized value must be rejected
        let transaction_id = [0u8; 12];
        let value = [0u8, 0x02, 0x12, 0x34, 1, 2, 3, 4];
        let resp = synthetic_response(&transaction_id, XOR_MAPPED_ADDRESS, &value);
        assert!(matches!(
            parse_stun_response(&resp),
            Err(StunError::InvalidResponse)
        ));
    }

    #[test]
    fn test_parse_mapped_address_v6_legacy() {
        // Legacy MAPPED-ADDRESS carries the address without XOR
        let transaction_id = [7u8; 12];
        let addr: std::net::Ipv6Addr = "2606:4700::1111".parse().expect("valid literal");
        let mut value = vec![0u8, 0x02, 0x0d, 0x96]; // port 3478, not XORed
        value.extend_from_slice(&addr.octets());
        let resp = synthetic_response(&transaction_id, MAPPED_ADDRESS, &value);
        let parsed = parse_stun_response(&resp).expect("legacy v6 response must parse");
        assert_eq!(parsed, IpAddr::V6(addr));
    }

    #[test]
    fn test_parse_xor_mapped_address_v4_still_works() {
        // Regression guard: the v4 un-XOR path is unchanged
        let transaction_id: [u8; 12] = [9u8; 12];
        let addr: std::net::Ipv4Addr = "203.0.113.7".parse().expect("valid literal");
        let cookie = STUN_MAGIC_COOKIE.to_be_bytes();
        let mut value = vec![0u8, 0x01, 0, 0];
        for (i, byte) in addr.octets().iter().enumerate() {
            value.push(byte ^ cookie[i]);
        }
        let resp = synthetic_response(&transaction_id, XOR_MAPPED_ADDRESS, &value);
        let parsed = parse_stun_response(&resp).expect("v4 response must parse");
        assert_eq!(parsed, IpAddr::V4(addr));
    }

    #[tokio::test]
    async fn test_stun_google() {
        // This test requires internet connectivity
        let cache = Arc::new(RwLock::new(crate::public_ip::stun_cache::StunCache::new()));
        let result = get_public_ip_stun_with_cache(
            "stun.l.google.com:19302",
            Duration::from_secs(2),
            &cache,
        )
        .await;

        match result {
            Ok(ip) => {
                println!("Detected public IP via STUN: {}", ip);
                // We can't assert a specific IP, but we can check it's valid
                match ip {
                    IpAddr::V4(v4) => {
                        assert!(!v4.is_private());
                        assert!(!v4.is_loopback());
                    }
                    IpAddr::V6(_) => {
                        // IPv6 is valid too
                    }
                }
            }
            Err(e) => {
                // Network errors are acceptable in tests
                eprintln!("STUN test failed (may be offline): {}", e);
            }
        }
    }
}
