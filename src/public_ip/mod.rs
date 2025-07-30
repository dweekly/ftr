//! Public IP detection functionality

pub mod providers;
pub mod stun;
pub mod stun_cache;

use crate::asn::lookup_asn;
use crate::traceroute::IspInfo;
use hickory_resolver::TokioResolver;
use std::sync::Arc;
use std::time::Duration;

pub use providers::{get_public_ip, PublicIpError, PublicIpProvider};
pub use stun::{get_public_ip_stun_with_fallback, StunError};

/// Detect ISP information from public IP using STUN (fast path)
pub async fn detect_isp_stun(
    resolver: Option<Arc<TokioResolver>>,
) -> Result<IspInfo, PublicIpError> {
    // Try STUN first (much faster than HTTPS)
    // Try STUN first (much faster than HTTPS)
    let public_ip = match get_public_ip_stun_with_fallback(Duration::from_millis(200)).await {
        Ok(ip) => ip,
        Err(_) => {
            // Fall back to HTTPS if STUN fails
            get_public_ip(PublicIpProvider::default()).await?
        }
    };

    // Only handle IPv4 for now
    let ipv4 = match public_ip {
        std::net::IpAddr::V4(ip) => ip,
        std::net::IpAddr::V6(_) => {
            return Err(PublicIpError::UnsupportedIpVersion);
        }
    };

    // Look up ASN information
    let asn_info = lookup_asn(ipv4, resolver.clone())
        .await
        .map_err(|e| PublicIpError::AsnLookupFailed(e.to_string()))?;

    // Look up reverse DNS for the public IP
    let hostname = crate::dns::reverse_dns_lookup(public_ip, resolver)
        .await
        .ok();

    Ok(IspInfo {
        public_ip,
        asn: asn_info.asn,
        name: asn_info.name,
        hostname,
    })
}

/// Detect ISP information from public IP using HTTPS (slow path)
pub async fn detect_isp(resolver: Option<Arc<TokioResolver>>) -> Result<IspInfo, PublicIpError> {
    // Get public IP first
    let public_ip = get_public_ip(PublicIpProvider::default()).await?;

    // Only handle IPv4 for now
    let ipv4 = match public_ip {
        std::net::IpAddr::V4(ip) => ip,
        std::net::IpAddr::V6(_) => {
            return Err(PublicIpError::UnsupportedIpVersion);
        }
    };

    // Look up ASN information
    let asn_info = lookup_asn(ipv4, resolver.clone())
        .await
        .map_err(|e| PublicIpError::AsnLookupFailed(e.to_string()))?;

    // Look up reverse DNS for the public IP
    let hostname = crate::dns::reverse_dns_lookup(public_ip, resolver)
        .await
        .ok();

    Ok(IspInfo {
        public_ip,
        asn: asn_info.asn,
        name: asn_info.name,
        hostname,
    })
}

/// Detect ISP with default resolver using STUN (fast)
pub async fn detect_isp_with_default_resolver() -> Result<IspInfo, PublicIpError> {
    let resolver = Arc::new(crate::dns::create_default_resolver());
    detect_isp_stun(Some(resolver)).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_detect_isp() {
        let result = detect_isp_with_default_resolver().await;
        // We can't assert on specific values as they depend on the test environment
        // But we can check that the function works
        match result {
            Ok(isp_info) => {
                assert!(isp_info.asn != 0, "ASN should not be 0");
                assert!(!isp_info.name.is_empty());
            }
            Err(e) => {
                // Network errors are okay in tests
                eprintln!(
                    "ISP detection failed (expected in some test environments): {}",
                    e
                );
            }
        }
    }
}
