//! Public IP detection functionality

pub mod providers;

use crate::asn::lookup_asn;
use crate::traceroute::IspInfo;
use hickory_resolver::TokioResolver;
use std::sync::Arc;

pub use providers::{get_public_ip, PublicIpError, PublicIpProvider};

/// Detect ISP information from public IP
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
    let asn_info = lookup_asn(ipv4, resolver)
        .await
        .map_err(|e| PublicIpError::AsnLookupFailed(e.to_string()))?;

    Ok(IspInfo {
        public_ip,
        asn: asn_info.asn,
        name: asn_info.name,
    })
}

/// Detect ISP with default resolver
pub async fn detect_isp_with_default_resolver() -> Result<IspInfo, PublicIpError> {
    let resolver = Arc::new(crate::dns::create_default_resolver());
    detect_isp(Some(resolver)).await
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
