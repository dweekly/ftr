//! STUN client for fast public IP detection
//!
//! This module implements a minimal STUN client to quickly determine
//! the public IP address. STUN is much faster than HTTPS because:
//! - Single UDP packet exchange (no TCP handshake)
//! - No TLS negotiation
//! - Minimal protocol overhead
//! - ~RTT latency instead of multiple round trips

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

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
#[derive(Debug, thiserror::Error)]
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

/// Get public IP using STUN protocol
pub async fn get_public_ip_stun(server: &str, timeout: Duration) -> Result<IpAddr, StunError> {
    let verbose = std::env::var("FTR_VERBOSE")
        .ok()
        .and_then(|v| v.parse::<u8>().ok())
        .unwrap_or(0);

    if verbose >= 2 {
        eprintln!("[STUN] Attempting to contact STUN server: {}", server);
    }

    // Get server addresses from cache
    let server_addrs = crate::public_ip::stun_cache::STUN_CACHE
        .get_stun_server_addrs(server)
        .await
        .map_err(|e| {
            if verbose >= 2 {
                eprintln!("[STUN] Failed to resolve {}: {}", server, e);
            }
            StunError::IoError(e)
        })?;

    // Try each address until one works
    for server_addr in server_addrs {
        if verbose >= 2 {
            eprintln!("[STUN] Trying {} (resolved from {})", server_addr, server);
        }
        match get_public_ip_stun_addr(server_addr, timeout).await {
            Ok(ip) => {
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
    // Use tokio's async UDP socket
    let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;

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

/// Get public IP using STUN with fallback to multiple servers
pub async fn get_public_ip_stun_with_fallback(timeout: Duration) -> Result<IpAddr, StunError> {
    // Pre-warm cache if not already done (this is fast if already cached)
    let _ = crate::public_ip::stun_cache::prewarm_stun_cache().await;

    // Check for custom STUN server from environment
    if let Ok(custom_server) = std::env::var("FTR_STUN_SERVER") {
        if let Ok(ip) = get_public_ip_stun(&custom_server, timeout).await {
            return Ok(ip);
        }
        // If custom server fails, fall back to default servers
    }

    // Try primary server first (Google's is most reliable)
    if let Ok(ip) = get_public_ip_stun(STUN_SERVERS[0], timeout).await {
        return Ok(ip);
    }

    // Fall back to other servers
    for server in &STUN_SERVERS[1..] {
        match get_public_ip_stun(server, timeout).await {
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
    getrandom::getrandom(&mut transaction_id).unwrap_or_else(|_| {
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
            XOR_MAPPED_ADDRESS => {
                // Parse XOR-MAPPED-ADDRESS
                if attr_length >= 8 {
                    return parse_xor_mapped_address(&data[offset + 4..offset + 4 + attr_length]);
                }
            }
            MAPPED_ADDRESS => {
                // Parse legacy MAPPED-ADDRESS
                if attr_length >= 8 {
                    return parse_mapped_address(&data[offset + 4..offset + 4 + attr_length]);
                }
            }
            _ => {}
        }

        // Move to next attribute (with padding to 4-byte boundary)
        offset += 4 + ((attr_length + 3) & !3);
    }

    Err(StunError::NoMappedAddress)
}

/// Parse XOR-MAPPED-ADDRESS attribute
fn parse_xor_mapped_address(data: &[u8]) -> Result<IpAddr, StunError> {
    if data.len() < 8 {
        return Err(StunError::InvalidResponse);
    }

    let family = data[1];
    let _port = u16::from_be_bytes([data[2], data[3]]) ^ (STUN_MAGIC_COOKIE >> 16) as u16;

    match family {
        0x01 => {
            // IPv4
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
            // IPv6 - not implemented yet
            Err(StunError::InvalidResponse)
        }
        _ => Err(StunError::InvalidResponse),
    }
}

/// Parse legacy MAPPED-ADDRESS attribute
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

    #[tokio::test]
    async fn test_stun_google() {
        // This test requires internet connectivity
        let result = get_public_ip_stun("stun.l.google.com:19302", Duration::from_secs(2)).await;

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
