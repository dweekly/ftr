//! Public IP detection functionality

pub mod providers;
pub mod service;
pub mod stun;
pub mod stun_cache;

use crate::services::Services;
use crate::traceroute::IspInfo;
use std::net::IpAddr;

pub use providers::{
    PUBLIC_IP_V6_URLS, PublicIpError, PublicIpProvider, get_public_ip, get_public_ip_v6_https,
};
pub use service::{PublicIps, StunClient};
pub use stun::StunError;

/// Detect ISP information from public IP using STUN (fast path) with services
pub async fn detect_isp_stun_with_services(services: &Services) -> Result<IspInfo, PublicIpError> {
    // Try STUN first (much faster than HTTPS)
    let public_ip = match services.stun.get_public_ip().await {
        Ok(ip) => ip,
        Err(_) => {
            // Fall back to HTTPS if STUN fails
            get_public_ip(PublicIpProvider::default()).await?
        }
    };

    // Look up ASN information
    let asn_info = services
        .asn
        .lookup(public_ip)
        .await
        .map_err(|e| PublicIpError::AsnLookupFailed(e.to_string()))?;

    // Look up reverse DNS for the public IP
    let hostname = services.rdns.lookup(public_ip).await.ok();

    Ok(IspInfo {
        public_ip,
        asn: asn_info.asn,
        name: asn_info.name,
        hostname,
    })
}

/// Detect ISP information for the IPv6 path using STUN (fast) with services
///
/// Discovers the public IPv6 address via STUN over UDPv6 (falling back to
/// IPv6-only HTTPS endpoints), then enriches it with ASN (Team Cymru
/// origin6 zone) and reverse DNS. Fails when the host has no IPv6
/// connectivity.
pub async fn detect_isp_v6_stun_with_services(
    services: &Services,
) -> Result<IspInfo, PublicIpError> {
    // Try STUN first (much faster than HTTPS)
    let public_ip = match services.stun.get_public_ip_v6().await {
        Ok(ip) => IpAddr::V6(ip),
        Err(_) => {
            // Fall back to HTTPS if STUN fails
            IpAddr::V6(get_public_ip_v6_https().await?)
        }
    };

    detect_isp_from_ip_with_services(public_ip, services).await
}

/// Detect ISP with default services using STUN (fast)
pub async fn detect_isp_with_default_services() -> Result<IspInfo, PublicIpError> {
    let services = Services::new();
    detect_isp_stun_with_services(&services).await
}

/// Detect ISP from a provided public IP address with services
pub async fn detect_isp_from_ip_with_services(
    public_ip: IpAddr,
    services: &Services,
) -> Result<IspInfo, PublicIpError> {
    // Look up ASN information
    let asn_info = services
        .asn
        .lookup(public_ip)
        .await
        .map_err(|e| PublicIpError::AsnLookupFailed(e.to_string()))?;

    // Look up reverse DNS for the public IP
    let hostname = services.rdns.lookup(public_ip).await.ok();

    Ok(IspInfo {
        public_ip,
        asn: asn_info.asn,
        name: asn_info.name,
        hostname,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_detect_isp() {
        let result = detect_isp_with_default_services().await;
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
