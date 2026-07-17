//! Live IPv6 traceroute integration tests
//!
//! These tests send real ICMPv6 probes over the network, so they are
//! opt-in: set `FTR_TEST_IPV6=1` to run them (GitHub-hosted runners have
//! no IPv6 connectivity, and even local machines may be v4-only). They
//! run unprivileged by design — the macOS DGRAM ICMPv6 path needs no root
//! (validated in docs/IPV6_DESIGN.md).
//!
//! ```bash
//! FTR_TEST_IPV6=1 cargo test --test ipv6_integration -- --nocapture
//! ```

use ftr::{Ftr, PreferredFamily, TracerouteConfig, TracerouteError};
use std::net::IpAddr;

/// Google Public DNS IPv6 anycast — the same reliable target the
/// validation spikes used.
const V6_TARGET: &str = "2001:4860:4860::8888";

/// Returns true (and prints why) when live IPv6 tests should be skipped.
fn skip_live_ipv6() -> bool {
    if std::env::var("FTR_TEST_IPV6").as_deref() != Ok("1") {
        eprintln!("Skipping live IPv6 test (set FTR_TEST_IPV6=1 to enable)");
        return true;
    }
    false
}

/// Assert an address renders in RFC 5952 canonical form: parsing its own
/// Display output must round-trip, and the string must be lowercase.
fn assert_canonical(addr: IpAddr) {
    let s = addr.to_string();
    assert_eq!(
        s.parse::<IpAddr>().expect("address string must re-parse"),
        addr,
        "address must round-trip through its Display form"
    );
    assert_eq!(
        s,
        s.to_lowercase(),
        "RFC 5952 requires lowercase hex digits"
    );
    assert!(!s.contains("%"), "IpAddr display never carries a zone");
}

#[tokio::test]
async fn test_live_ipv6_trace_to_google_dns() {
    if skip_live_ipv6() {
        return;
    }

    let config = TracerouteConfig::builder()
        .target(V6_TARGET)
        .max_hops(30)
        // Enrichment intentionally left enabled: classification must
        // degrade gracefully, not crash, even before v6 ASN enrichment
        // lands (it ships in a concurrent PR).
        .build()
        .expect("config builds");

    let ftr = Ftr::new();
    let result = ftr.trace_with_config(config).await;
    if matches!(result, Err(TracerouteError::Ipv6NotSupported)) {
        // Non-macOS platforms: typed error is the correct outcome.
        eprintln!("IPv6 probing not supported on this platform — typed error OK");
        return;
    }
    let result = result.expect("live IPv6 trace should succeed");

    assert_eq!(
        result.target_ip,
        V6_TARGET.parse::<IpAddr>().expect("valid literal")
    );
    assert!(
        result.destination_reached,
        "destination {V6_TARGET} should be reached"
    );

    // At least one intermediate hop (an address that is not the target)
    // must have answered — proof the Time Exceeded path works.
    let intermediate_hops: Vec<_> = result
        .hops
        .iter()
        .filter(|h| h.addr.is_some() && h.addr != Some(result.target_ip))
        .collect();
    assert!(
        !intermediate_hops.is_empty(),
        "expected at least one intermediate hop, got only: {:?}",
        result.hops
    );

    // Every responding hop must be IPv6 and render canonically.
    for hop in result.hops.iter().filter_map(|h| h.addr) {
        assert!(hop.is_ipv6(), "IPv6 trace must not report IPv4 hops: {hop}");
        assert_canonical(hop);
    }

    eprintln!(
        "live IPv6 trace: {} hops, {} intermediate, destination reached in {:?}",
        result.hop_count(),
        intermediate_hops.len(),
        result.total_duration
    );
    for hop in &result.hops {
        eprintln!(
            "  {:2} [{}] {:?} {:?}",
            hop.ttl, hop.segment, hop.addr, hop.rtt
        );
    }
}

#[tokio::test]
async fn test_live_ipv6_hostname_resolution_forced_v6() {
    if skip_live_ipv6() {
        return;
    }

    // google.com is dual-stack; -6 must yield an IPv6 address.
    let ip = ftr::resolve_target_with_family("google.com", PreferredFamily::V6)
        .await
        .expect("google.com must resolve under -6");
    assert!(ip.is_ipv6(), "forced V6 resolution returned {ip}");
    assert_canonical(ip);

    // Auto on a dual-stack host prefers IPv4 (documented conservative
    // default while v6 probing is new).
    let ip = ftr::resolve_target_with_family("google.com", PreferredFamily::Auto)
        .await
        .expect("google.com must resolve under Auto");
    assert!(ip.is_ipv4(), "Auto must prefer IPv4 for dual-stack hosts");
}

#[tokio::test]
async fn test_live_ipv6_trace_via_hostname() {
    if skip_live_ipv6() {
        return;
    }

    let config = TracerouteConfig::builder()
        .target("google.com")
        .preferred_family(PreferredFamily::V6)
        .max_hops(30)
        .build()
        .expect("config builds");

    let ftr = Ftr::new();
    let result = ftr.trace_with_config(config).await;
    if matches!(result, Err(TracerouteError::Ipv6NotSupported)) {
        eprintln!("IPv6 probing not supported on this platform — typed error OK");
        return;
    }
    let result = result.expect("live IPv6 hostname trace should succeed");

    assert!(result.target_ip.is_ipv6(), "-6 trace must probe IPv6");
    assert!(
        result.destination_reached,
        "google.com over IPv6 should be reachable"
    );
}
