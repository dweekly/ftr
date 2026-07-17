//! Public IP providers

use std::net::{IpAddr, Ipv6Addr};
use std::time::Duration;

/// Error type for public IP detection
///
/// This enum is `#[non_exhaustive]`: new error variants may be added in
/// minor releases, so downstream matches must include a wildcard arm.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
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

    /// Other error
    #[error("{0}")]
    Other(String),
}

/// Public IP provider services
///
/// This enum is `#[non_exhaustive]`: new providers may be added in minor
/// releases, so downstream matches must include a wildcard arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
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

/// IPv6-only HTTPS public-IP endpoints, tried in order by
/// [`get_public_ip_v6_https`].
///
/// These hostnames publish only AAAA records, which forces the connection
/// (and therefore the reported source address) over IPv6. The dual-stack
/// `api64.ipify.org` is deliberately absent: it may answer over IPv4.
/// Both endpoints verified live on 2026-07-16 to return the same address
/// as STUN over UDPv6 (see `examples/spike_stun6.rs`).
pub const PUBLIC_IP_V6_URLS: &[&str] = &["https://api6.ipify.org", "https://ipv6.icanhazip.com"];

/// Get public IP address from a specific provider
pub async fn get_public_ip_from_provider(
    provider: PublicIpProvider,
    timeout: Duration,
) -> Result<IpAddr, PublicIpError> {
    fetch_ip_from_url(provider.url().to_string(), timeout).await
}

/// Fetch an IP address from an HTTPS plain-text "what is my IP" endpoint
async fn fetch_ip_from_url(url: String, timeout: Duration) -> Result<IpAddr, PublicIpError> {
    let ip_str = tokio::task::spawn_blocking(move || {
        // This crate builds ureq with default-features = false and only the
        // "native-tls" feature (see Cargo.toml), but ureq 3's default TLS
        // provider is Rustls — using it without the "rustls" feature panics
        // at request time ("provider is Rustls but feature is not
        // enabled"). Select the native-tls provider explicitly, per the
        // ureq 3 docs (ureq-3.3.0/src/lib.rs "Rustls and Native TLS"
        // section).
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_global(Some(timeout))
            .tls_config(
                ureq::tls::TlsConfig::builder()
                    .provider(ureq::tls::TlsProvider::NativeTls)
                    .build(),
            )
            .build()
            .into();
        let body = agent
            .get(&url)
            .call()
            .map_err(|e| match e {
                ureq::Error::Timeout(_) => PublicIpError::Timeout,
                other => PublicIpError::HttpError(other.to_string()),
            })?
            .body_mut()
            .read_to_string()
            .map_err(|e| PublicIpError::HttpError(e.to_string()))?;
        Ok::<String, PublicIpError>(body)
    })
    .await
    .map_err(|e| PublicIpError::HttpError(e.to_string()))??;

    ip_str
        .trim()
        .parse::<IpAddr>()
        .map_err(|e| PublicIpError::ParseError(format!("{e}: {}", ip_str.trim())))
}

/// Get public IP address, trying multiple providers if necessary
pub async fn get_public_ip(preferred_provider: PublicIpProvider) -> Result<IpAddr, PublicIpError> {
    let timeout = Duration::from_secs(5);

    // Try preferred provider first
    match get_public_ip_from_provider(preferred_provider, timeout).await {
        Ok(ip) => return Ok(ip),
        Err(_) => {
            // Continue to next provider
        }
    }

    // Try other providers
    for provider in PublicIpProvider::all() {
        if *provider == preferred_provider {
            continue; // Already tried
        }

        match get_public_ip_from_provider(*provider, timeout).await {
            Ok(ip) => return Ok(ip),
            Err(_) => {
                // Continue to next provider
            }
        }
    }

    Err(PublicIpError::AllProvidersFailed)
}

/// Get the public IPv6 address over HTTPS, trying the endpoints in
/// [`PUBLIC_IP_V6_URLS`] in order
///
/// This is the HTTPS fallback for the STUN-based
/// [`StunClient::get_public_ip_v6`](crate::public_ip::StunClient::get_public_ip_v6).
/// Fails with [`PublicIpError::AllProvidersFailed`] when the host has no
/// IPv6 connectivity.
pub async fn get_public_ip_v6_https() -> Result<Ipv6Addr, PublicIpError> {
    // Same per-attempt budget as the v4 get_public_ip path
    let timeout = Duration::from_secs(5);

    for url in PUBLIC_IP_V6_URLS {
        match fetch_ip_from_url((*url).to_string(), timeout).await {
            // The endpoints are v6-only so a v4 answer should be
            // impossible; skip such an endpoint rather than mislabel it.
            Ok(IpAddr::V6(v6)) => return Ok(v6),
            Ok(IpAddr::V4(_)) | Err(_) => continue,
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

    #[tokio::test]
    async fn test_get_public_ip_from_each_provider() {
        let timeout = Duration::from_secs(10);

        for provider in PublicIpProvider::all() {
            let result = get_public_ip_from_provider(*provider, timeout).await;
            match result {
                Ok(ip) => {
                    eprintln!("Provider {} returned IP: {}", provider.url(), ip);
                    assert!(matches!(ip, IpAddr::V4(_) | IpAddr::V6(_)));
                }
                Err(e) => {
                    eprintln!("Provider {} failed: {}", provider.url(), e);
                }
            }
        }
    }

    #[tokio::test]
    async fn test_provider_failover() {
        let result = get_public_ip(PublicIpProvider::ICanHazIp).await;

        assert!(
            matches!(&result, Ok(_) | Err(PublicIpError::AllProvidersFailed)),
            "Unexpected error type: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn test_timeout_handling() {
        // Hermetic timeout test: a local listener that accepts connections
        // but never responds guarantees the request cannot complete,
        // regardless of network conditions or ureq's sub-millisecond timer
        // behavior (a live 1ms-timeout variant of this test flaked on CI).
        let listener =
            std::net::TcpListener::bind("127.0.0.1:0").expect("bind local test listener");
        let port = listener
            .local_addr()
            .expect("local listener has an address")
            .port();
        // Keep the listener alive but never accept/respond.
        let url = format!("http://127.0.0.1:{port}/");

        let result = fetch_ip_from_url(url, Duration::from_millis(100)).await;

        let err = result.expect_err("unresponsive endpoint must time out");
        assert!(
            matches!(err, PublicIpError::Timeout | PublicIpError::HttpError(_)),
            "Unexpected error type: {}",
            err
        );
        drop(listener);
    }

    #[test]
    fn test_error_display() {
        let errors = vec![
            PublicIpError::HttpError("connection failed".to_string()),
            PublicIpError::ParseError("invalid IP".to_string()),
            PublicIpError::Timeout,
            PublicIpError::AllProvidersFailed,
            PublicIpError::UnsupportedIpVersion,
            PublicIpError::AsnLookupFailed("lookup failed".to_string()),
        ];

        for error in errors {
            let error_str = error.to_string();
            assert!(!error_str.is_empty());

            match error {
                PublicIpError::HttpError(msg) => assert!(error_str.contains(&msg)),
                PublicIpError::ParseError(msg) => assert!(error_str.contains(&msg)),
                PublicIpError::Timeout => assert!(error_str.contains("timed out")),
                PublicIpError::AllProvidersFailed => assert!(error_str.contains("All")),
                PublicIpError::UnsupportedIpVersion => assert!(error_str.contains("IPv6")),
                PublicIpError::AsnLookupFailed(msg) => assert!(error_str.contains(&msg)),
                PublicIpError::Other(msg) => assert!(error_str.contains(&msg)),
            }
        }
    }

    #[test]
    fn test_provider_equality() {
        assert_eq!(PublicIpProvider::AwsCheckIp, PublicIpProvider::AwsCheckIp);
        assert_ne!(PublicIpProvider::AwsCheckIp, PublicIpProvider::Ipify);

        let preferred = PublicIpProvider::Ipify;
        let mut tried_count = 0;
        for provider in PublicIpProvider::all() {
            if *provider == preferred {
                continue;
            }
            tried_count += 1;
        }
        assert_eq!(tried_count, 2);
    }
}
