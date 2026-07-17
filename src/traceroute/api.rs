//! Async high-level traceroute API
//!
//! This module provides the async API for performing traceroute operations
//! with immediate response processing using Tokio.

use crate::dns::resolver;
use crate::services::Services;
use crate::socket::factory::create_probe_socket_with_options_and_verbose;
use crate::traceroute::config::PreferredFamily;
use crate::traceroute::engine::TracerouteEngine;
use crate::traceroute::{TracerouteConfig, TracerouteError, TracerouteResult};
use std::net::IpAddr;

/// Async traceroute API
#[derive(Debug)]
pub struct Traceroute {
    config: TracerouteConfig,
    target_ip: IpAddr,
    services: Option<Services>,
}

impl Traceroute {
    /// Create a new async traceroute from configuration with injected services
    pub async fn new_with_services(
        mut config: TracerouteConfig,
        services: Services,
    ) -> Result<Self, TracerouteError> {
        let target_ip = Self::resolve_target(&mut config).await?;

        Ok(Self {
            config,
            target_ip,
            services: Some(services),
        })
    }

    /// Resolve the target hostname/IP to an IpAddr, honoring the
    /// configuration's family preference
    async fn resolve_target(config: &mut TracerouteConfig) -> Result<IpAddr, TracerouteError> {
        // IP literals and "localhost" resolve deterministically and take
        // precedence over a pre-set target_ip (pre-0.9 precedence order).
        let target_is_literal =
            config.target.parse::<IpAddr>().is_ok() || config.target == "localhost";

        if !target_is_literal {
            // Already resolved (skips DNS): validate the family preference
            // still holds, then use it.
            if let Some(ip) = config.target_ip {
                check_family(ip, config.preferred_family, &config.target)?;
                return Ok(ip);
            }
        }

        let ip = resolve_target_with_family(&config.target, config.preferred_family).await?;
        config.target_ip = Some(ip);
        Ok(ip)
    }

    /// Create a new async traceroute from configuration (uses global caches)
    pub async fn new(mut config: TracerouteConfig) -> Result<Self, TracerouteError> {
        let target_ip = Self::resolve_target(&mut config).await?;

        Ok(Self {
            config,
            target_ip,
            services: None,
        })
    }

    /// Run the async traceroute
    pub async fn run(self) -> Result<TracerouteResult, TracerouteError> {
        // Use timing config from traceroute config, but override socket_read_timeout with probe_timeout
        let mut timing_config = self.config.timing.clone();
        timing_config.socket_read_timeout = self.config.probe_timeout;

        // Create socket with protocol preference; verbosity is passed
        // explicitly (never via environment variables, which would race
        // between concurrent traces in the same process)
        let socket = create_probe_socket_with_options_and_verbose(
            self.target_ip,
            timing_config,
            self.config.protocol,
            self.config.socket_mode,
            self.config.verbose,
        )
        .await?;

        // Create and run fully parallel async engine. Engine errors are
        // already TracerouteError values; propagate them unchanged so typed
        // variants (e.g. Ipv6NotSupported, InsufficientPermissions) survive.
        let engine = if let Some(services) = self.services {
            TracerouteEngine::new_with_services(
                socket,
                self.config.clone(),
                self.target_ip,
                std::sync::Arc::new(services),
            )
            .await?
        } else {
            TracerouteEngine::new(socket, self.config.clone(), self.target_ip).await?
        };

        let result = engine.run().await?;

        // The fully parallel engine handles enrichment internally, so we can just return
        Ok(result)
    }
}

/// Validate that a resolved/literal address matches an explicit family
/// preference. `Auto` accepts either family; the family always lives in the
/// error *message* (context), never in a distinct error type.
fn check_family(ip: IpAddr, family: PreferredFamily, target: &str) -> Result<(), TracerouteError> {
    match (family, ip) {
        (PreferredFamily::V4, IpAddr::V6(_)) => Err(TracerouteError::ResolutionError(format!(
            "{target} is an IPv6 address but IPv4 was requested (-4)"
        ))),
        (PreferredFamily::V6, IpAddr::V4(_)) => Err(TracerouteError::ResolutionError(format!(
            "{target} is an IPv4 address but IPv6 was requested (-6)"
        ))),
        _ => Ok(()),
    }
}

/// Resolve a traceroute target (IP literal or hostname) to a single address
/// of the preferred family.
///
/// - **IP literals** are used directly; an explicit `V4`/`V6` preference
///   that contradicts the literal's family is a
///   [`TracerouteError::ResolutionError`].
/// - **`localhost`** short-circuits to `127.0.0.1` (or `::1` under
///   [`PreferredFamily::V6`]) without touching DNS.
/// - **Hostnames** resolve per the preference. `V4` uses ftr's own DNS
///   resolver (A query) exactly as previous releases did. `V6` uses the
///   system resolver (`getaddrinfo` via tokio's `lookup_host`) and keeps
///   only IPv6 addresses; the system resolver is used deliberately so OS
///   facilities like macOS NAT64/DNS64 synthesis apply. `Auto` prefers
///   IPv4 and only falls back to IPv6 when no A records exist (see
///   [`PreferredFamily`] for why this conservative default was chosen).
///
/// Zone-scoped literals (`fe80::1%en0`) are rejected with a clear error
/// rather than silently stripping the zone: `IpAddr` cannot carry a scope
/// id, and tracerouting a link-local neighbor is a single-hop affair.
/// First-class scoped-target support needs an API extension (deferred).
pub async fn resolve_target_with_family(
    target: &str,
    family: PreferredFamily,
) -> Result<IpAddr, TracerouteError> {
    // Zone-scoped IPv6 literal: refuse loudly, never strip the zone.
    if let Some((addr_part, zone)) = target.split_once('%') {
        if addr_part.parse::<std::net::Ipv6Addr>().is_ok() {
            return Err(TracerouteError::ResolutionError(format!(
                "zone-scoped IPv6 targets ({addr_part}%{zone}) are not yet supported"
            )));
        }
    }

    // IP literal: use as-is (after family validation).
    if let Ok(ip) = target.parse::<IpAddr>() {
        check_family(ip, family, target)?;
        return Ok(ip);
    }

    // Well-known hostname, no DNS needed.
    if target == "localhost" {
        return Ok(match family {
            PreferredFamily::V6 => IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
            _ => IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        });
    }

    match family {
        PreferredFamily::V4 => resolve_first_a(target).await,
        PreferredFamily::V6 => resolve_first_aaaa(target).await,
        _ => {
            // Auto: IPv4 first — identical mechanism and result to pre-0.9
            // releases for any host with A records — then IPv6.
            match resolve_first_a(target).await {
                Ok(ip) => Ok(ip),
                Err(v4_err) => match resolve_first_aaaa(target).await {
                    Ok(ip) => Ok(ip),
                    Err(_) => Err(v4_err),
                },
            }
        }
    }
}

/// Resolve a hostname's first A record via ftr's own DNS resolver — the
/// exact IPv4 mechanism used by previous releases.
async fn resolve_first_a(target: &str) -> Result<IpAddr, TracerouteError> {
    let addrs = resolver::resolve_a(target)
        .await
        .map_err(|e| TracerouteError::ResolutionError(format!("{target}: {e}")))?;
    addrs
        .first()
        .map(|a| IpAddr::V4(*a))
        .ok_or_else(|| TracerouteError::ResolutionError(format!("{target}: no IPv4 addresses")))
}

/// Resolve a hostname's first IPv6 address via the system resolver
/// (`getaddrinfo`), so OS-level behaviors (NAT64/DNS64 synthesis,
/// /etc/hosts entries) apply to IPv6 targets.
async fn resolve_first_aaaa(target: &str) -> Result<IpAddr, TracerouteError> {
    let addrs = tokio::net::lookup_host((target, 0))
        .await
        .map_err(|e| TracerouteError::ResolutionError(format!("{target}: {e}")))?;
    addrs
        .into_iter()
        .find(std::net::SocketAddr::is_ipv6)
        .map(|a| a.ip())
        .ok_or_else(|| {
            TracerouteError::ResolutionError(format!("{target}: no IPv6 (AAAA) addresses"))
        })
}

/// Run an async traceroute with the given configuration
pub async fn trace_async(target: &str) -> Result<TracerouteResult, TracerouteError> {
    // ConfigError converts into TracerouteError::ConfigError via #[from]
    let config = TracerouteConfig::builder().target(target).build()?;
    trace_with_config_async(config).await
}

/// Run an async traceroute with a custom configuration
pub async fn trace_with_config_async(
    config: TracerouteConfig,
) -> Result<TracerouteResult, TracerouteError> {
    let traceroute = Traceroute::new(config).await?;
    traceroute.run().await
}

/// Run an async traceroute with injected services (internal API for Ftr struct)
pub(crate) async fn trace_with_services(
    config: TracerouteConfig,
    services: &Services,
) -> Result<TracerouteResult, TracerouteError> {
    let traceroute = Traceroute::new_with_services(config, services.clone()).await?;
    traceroute.run().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn test_async_traceroute_creation() {
        let config = TracerouteConfig::builder()
            .target("127.0.0.1")
            .build()
            .expect("failed to build traceroute config");

        let result = Traceroute::new(config).await;
        assert!(result.is_ok());

        let traceroute = result.expect("Traceroute creation should succeed");
        assert_eq!(
            traceroute.target_ip,
            IpAddr::V4("127.0.0.1".parse().expect("valid IPv4 address"))
        );
    }

    #[tokio::test]
    async fn test_async_traceroute_ipv6_literal_resolves() {
        // IPv6 literals now resolve at creation time; platforms without
        // IPv6 probe support surface Ipv6NotSupported later, from the
        // socket factory, when the trace runs.
        let config = TracerouteConfig::builder()
            .target("::1")
            .target_ip(IpAddr::V6("::1".parse().expect("valid IPv6 address")))
            .build()
            .expect("failed to build traceroute config");

        let traceroute = Traceroute::new(config)
            .await
            .expect("IPv6 literal must resolve");
        assert_eq!(
            traceroute.target_ip,
            IpAddr::V6("::1".parse().expect("valid IPv6 address"))
        );
    }

    #[tokio::test]
    async fn test_resolve_ip_literals_by_family() {
        use crate::traceroute::config::PreferredFamily;

        // Literals pass through untouched under Auto and their own family.
        for family in [PreferredFamily::Auto, PreferredFamily::V4] {
            let ip = resolve_target_with_family("8.8.8.8", family)
                .await
                .expect("v4 literal resolves");
            assert_eq!(ip, IpAddr::V4("8.8.8.8".parse().expect("valid IPv4")));
        }
        for family in [PreferredFamily::Auto, PreferredFamily::V6] {
            let ip = resolve_target_with_family("2001:4860:4860::8888", family)
                .await
                .expect("v6 literal resolves");
            assert_eq!(
                ip,
                IpAddr::V6("2001:4860:4860::8888".parse().expect("valid IPv6"))
            );
        }

        // Family/literal contradictions are resolution errors whose message
        // carries the family context (no dedicated error type).
        let err = resolve_target_with_family("8.8.8.8", PreferredFamily::V6)
            .await
            .expect_err("v4 literal under -6 must fail");
        assert!(matches!(&err, TracerouteError::ResolutionError(m) if m.contains("IPv6")));

        let err = resolve_target_with_family("2001:4860:4860::8888", PreferredFamily::V4)
            .await
            .expect_err("v6 literal under -4 must fail");
        assert!(matches!(&err, TracerouteError::ResolutionError(m) if m.contains("IPv4")));
    }

    #[tokio::test]
    async fn test_resolve_localhost_by_family() {
        use crate::traceroute::config::PreferredFamily;

        assert_eq!(
            resolve_target_with_family("localhost", PreferredFamily::Auto)
                .await
                .expect("localhost resolves"),
            IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
        );
        assert_eq!(
            resolve_target_with_family("localhost", PreferredFamily::V6)
                .await
                .expect("localhost -6 resolves"),
            IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
        );
    }

    #[tokio::test]
    async fn test_resolve_rejects_zone_scoped_literal() {
        use crate::traceroute::config::PreferredFamily;

        // The zone must never be silently stripped; scoped targets are a
        // clear, typed error until the API can carry a scope id end-to-end.
        let err = resolve_target_with_family("fe80::1%en0", PreferredFamily::Auto)
            .await
            .expect_err("zone-scoped literal must be rejected");
        assert!(
            matches!(&err, TracerouteError::ResolutionError(m) if m.contains("zone-scoped")),
            "unexpected error: {err:?}"
        );
    }

    #[tokio::test]
    async fn test_async_traceroute_with_ip() {
        let config = TracerouteConfig::builder()
            .target("8.8.8.8")
            .target_ip(IpAddr::V4("8.8.8.8".parse().expect("valid IPv4 address")))
            .build()
            .expect("failed to build traceroute config");

        let result = Traceroute::new(config).await;
        assert!(result.is_ok());

        let traceroute = result.expect("Traceroute creation should succeed");
        assert_eq!(
            traceroute.target_ip,
            IpAddr::V4("8.8.8.8".parse().expect("valid IPv4 address"))
        );
    }

    #[tokio::test]
    async fn test_trace_async_localhost() {
        // This may fail due to permissions, but should at least parse correctly
        let result = trace_async("127.0.0.1").await;

        // Either succeeds, fails with permissions, or fails creating a socket
        assert!(
            matches!(
                &result,
                Ok(_)
                    | Err(TracerouteError::InsufficientPermissions { .. })
                    | Err(TracerouteError::SocketError(_))
            ),
            "Unexpected error: {:?}",
            result
        );
        if let Ok(trace_result) = result {
            assert_eq!(trace_result.target, "127.0.0.1");
        }
    }

    #[tokio::test]
    async fn test_trace_with_config_async() {
        let config = TracerouteConfig::builder()
            .target("127.0.0.1")
            .max_hops(3)
            .probe_timeout(Duration::from_millis(100))
            .build()
            .expect("failed to build traceroute config");

        let result = trace_with_config_async(config).await;

        // Either succeeds, fails with permissions, or fails creating a socket
        assert!(
            matches!(
                &result,
                Ok(_)
                    | Err(TracerouteError::InsufficientPermissions { .. })
                    | Err(TracerouteError::SocketError(_))
            ),
            "Unexpected error: {:?}",
            result
        );
        if let Ok(trace_result) = result {
            assert_eq!(trace_result.target, "127.0.0.1");
            assert!(trace_result.hops.len() <= 3);
        }
    }

    #[tokio::test]
    async fn test_async_traceroute_hostname_resolution() {
        let config = TracerouteConfig::builder()
            .target("localhost")
            .build()
            .expect("failed to build traceroute config");

        let result = Traceroute::new(config).await;
        assert!(result.is_ok());

        let traceroute = result.expect("Traceroute creation should succeed");
        // localhost should resolve to 127.0.0.1
        assert_eq!(
            traceroute.target_ip,
            IpAddr::V4("127.0.0.1".parse().expect("valid IPv4 address"))
        );
    }

    #[tokio::test]
    async fn test_async_traceroute_invalid_hostname() {
        let config = TracerouteConfig::builder()
            .target("this.hostname.definitely.does.not.exist.invalid")
            .build()
            .expect("failed to build traceroute config");

        let result = Traceroute::new(config).await;
        assert!(
            matches!(&result, Err(TracerouteError::ResolutionError(_))),
            "Expected resolution error, got: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn test_verbose_config_does_not_touch_environment() {
        let config = TracerouteConfig::builder()
            .target("127.0.0.1")
            .verbose(2)
            .max_hops(1) // Limit hops to make test faster
            .probe_timeout(Duration::from_millis(100))
            .build()
            .expect("failed to build traceroute config");
        assert_eq!(config.verbose, 2);

        let traceroute = Traceroute::new(config)
            .await
            .expect("Traceroute creation for localhost should succeed");

        // Verbosity is threaded through explicitly; running a trace must not
        // mutate process-global environment state (which would race between
        // concurrent traces)
        let before = std::env::var("FTR_VERBOSE").ok();
        let _ = tokio::time::timeout(Duration::from_secs(5), traceroute.run()).await;
        assert_eq!(std::env::var("FTR_VERBOSE").ok(), before);
    }
}
