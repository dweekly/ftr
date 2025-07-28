//! Public IP providers

use std::net::IpAddr;
use std::time::Duration;

/// Error type for public IP detection
#[derive(Debug, thiserror::Error)]
pub enum PublicIpError {
    /// HTTP request failed
    #[error("HTTP request failed: {0}")]
    HttpError(String),

    /// Failed to parse IP address
    #[error("Failed to parse IP address: {0}")]
    ParseError(String),

    /// Request timeout
    #[error("Request timed out")]
    Timeout,

    /// All providers failed
    #[error("All public IP providers failed")]
    AllProvidersFailed,

    /// Unsupported IP version (IPv6)
    #[error("IPv6 is not yet supported")]
    UnsupportedIpVersion,

    /// ASN lookup failed
    #[error("ASN lookup failed: {0}")]
    AsnLookupFailed(String),
}

/// Public IP provider services
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PublicIpProvider {
    /// AWS checkip service
    #[default]
    AwsCheckIp,
    /// ipify.org service
    Ipify,
    /// icanhazip.com service
    ICanHazIp,
}

impl PublicIpProvider {
    /// Get the URL for this provider
    pub fn url(&self) -> &'static str {
        match self {
            PublicIpProvider::AwsCheckIp => "https://checkip.amazonaws.com",
            PublicIpProvider::Ipify => "https://api.ipify.org",
            PublicIpProvider::ICanHazIp => "https://icanhazip.com",
        }
    }

    /// Get all available providers
    pub fn all() -> &'static [PublicIpProvider] {
        &[
            PublicIpProvider::AwsCheckIp,
            PublicIpProvider::Ipify,
            PublicIpProvider::ICanHazIp,
        ]
    }
}

/// Get public IP address from a specific provider
pub async fn get_public_ip_from_provider(
    provider: PublicIpProvider,
    timeout: Duration,
) -> Result<IpAddr, PublicIpError> {
    let client = reqwest::Client::builder()
        .timeout(timeout)
        .build()
        .map_err(|e| PublicIpError::HttpError(e.to_string()))?;

    let response = client.get(provider.url()).send().await.map_err(|e| {
        if e.is_timeout() {
            PublicIpError::Timeout
        } else {
            PublicIpError::HttpError(e.to_string())
        }
    })?;

    let ip_str = response
        .text()
        .await
        .map_err(|e| PublicIpError::HttpError(e.to_string()))?
        .trim()
        .to_string();

    ip_str
        .parse::<IpAddr>()
        .map_err(|e| PublicIpError::ParseError(format!("{e}: {ip_str}")))
}

/// Get public IP address, trying multiple providers if necessary
pub async fn get_public_ip(preferred_provider: PublicIpProvider) -> Result<IpAddr, PublicIpError> {
    let timeout = Duration::from_secs(5);

    // Try preferred provider first
    match get_public_ip_from_provider(preferred_provider, timeout).await {
        Ok(ip) => return Ok(ip),
        Err(e) => {
            eprintln!("Warning: {} failed: {}", preferred_provider.url(), e);
        }
    }

    // Try other providers
    for provider in PublicIpProvider::all() {
        if *provider == preferred_provider {
            continue; // Already tried
        }

        match get_public_ip_from_provider(*provider, timeout).await {
            Ok(ip) => return Ok(ip),
            Err(e) => {
                eprintln!("Warning: {} failed: {}", provider.url(), e);
            }
        }
    }

    Err(PublicIpError::AllProvidersFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_urls() {
        assert_eq!(
            PublicIpProvider::AwsCheckIp.url(),
            "https://checkip.amazonaws.com"
        );
        assert_eq!(PublicIpProvider::Ipify.url(), "https://api.ipify.org");
        assert_eq!(PublicIpProvider::ICanHazIp.url(), "https://icanhazip.com");
    }

    #[test]
    fn test_provider_all() {
        let providers = PublicIpProvider::all();
        assert_eq!(providers.len(), 3);
        assert!(providers.contains(&PublicIpProvider::AwsCheckIp));
        assert!(providers.contains(&PublicIpProvider::Ipify));
        assert!(providers.contains(&PublicIpProvider::ICanHazIp));
    }

    #[test]
    fn test_default_provider() {
        assert_eq!(PublicIpProvider::default(), PublicIpProvider::AwsCheckIp);
    }

    #[tokio::test]
    #[ignore] // Ignore in CI as it requires network access
    async fn test_get_public_ip() {
        let result = get_public_ip(PublicIpProvider::default()).await;
        match result {
            Ok(ip) => {
                // Should be a valid public IP
                match ip {
                    IpAddr::V4(ipv4) => {
                        assert!(!ipv4.is_private());
                        assert!(!ipv4.is_loopback());
                        assert!(!ipv4.is_link_local());
                    }
                    IpAddr::V6(ipv6) => {
                        assert!(!ipv6.is_loopback());
                    }
                }
            }
            Err(e) => {
                // Network errors are okay in tests
                eprintln!(
                    "Public IP detection failed (expected in some test environments): {}",
                    e
                );
            }
        }
    }
}
