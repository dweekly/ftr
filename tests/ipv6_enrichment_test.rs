//! Live integration tests for IPv6 enrichment: Team Cymru origin6 ASN
//! lookup and STUN-over-UDPv6 public IP detection.
//!
//! These tests require real dual-stack IPv6 connectivity and are gated
//! behind `FTR_TEST_IPV6=1` so CI runners without IPv6 skip them:
//!
//! ```bash
//! FTR_TEST_IPV6=1 cargo test --test ipv6_enrichment_test -- --nocapture
//! ```

use ftr::Ftr;
use std::net::{IpAddr, Ipv6Addr};

/// Returns true (and prints a notice) when live IPv6 tests are not enabled.
fn skip_unless_ipv6_enabled(test_name: &str) -> bool {
    if std::env::var("FTR_TEST_IPV6").is_err() {
        eprintln!("{test_name}: skipped (set FTR_TEST_IPV6=1 to run live IPv6 tests)");
        return true;
    }
    false
}

#[tokio::test]
async fn test_live_asn_lookup_v6_google_dns() {
    if skip_unless_ipv6_enabled("test_live_asn_lookup_v6_google_dns") {
        return;
    }

    let ftr = Ftr::new();
    let ip: IpAddr = "2001:4860:4860::8888".parse().expect("valid IP");
    let info = ftr
        .lookup_asn(ip)
        .await
        .expect("origin6 lookup for Google DNS should succeed");

    eprintln!(
        "2001:4860:4860::8888 => AS{} {} ({} / {} / {})",
        info.asn, info.name, info.prefix, info.country_code, info.registry
    );
    assert_eq!(info.asn, 15169, "Google DNS v6 should be AS15169");
    assert!(
        info.name.contains("GOOGLE"),
        "AS name should contain GOOGLE, got '{}'",
        info.name
    );
    assert_eq!(info.prefix, "2001:4860::/32");
}

#[tokio::test]
async fn test_live_asn_lookup_v6_own_public_ip() {
    if skip_unless_ipv6_enabled("test_live_asn_lookup_v6_own_public_ip") {
        return;
    }

    let ftr = Ftr::new();
    let public_v6 = ftr
        .get_public_ip_v6()
        .await
        .expect("machine should have public IPv6 (FTR_TEST_IPV6 is set)");

    let info = ftr
        .lookup_asn(IpAddr::V6(public_v6))
        .await
        .expect("ASN lookup of own public IPv6 should succeed");

    eprintln!(
        "own public IPv6 {public_v6} => AS{} {}",
        info.asn, info.name
    );
    assert_ne!(info.asn, 0, "own public IPv6 should map to a real ASN");
    assert!(!info.name.is_empty(), "AS name should be populated");
}

#[tokio::test]
async fn test_live_stun_v6_matches_https_v6() {
    if skip_unless_ipv6_enabled("test_live_stun_v6_matches_https_v6") {
        return;
    }

    // STUN over UDPv6 and an independent v6-only HTTPS endpoint must agree
    // on the public IPv6 address.
    let ftr = Ftr::new();
    let stun_v6: Ipv6Addr = ftr
        .get_public_ip_v6()
        .await
        .expect("STUN v6 should succeed on a dual-stack network");
    let https_v6 = ftr::public_ip::get_public_ip_v6_https()
        .await
        .expect("HTTPS v6 endpoint should succeed on a dual-stack network");

    eprintln!("STUN v6: {stun_v6}, HTTPS v6: {https_v6}");
    assert_eq!(
        stun_v6, https_v6,
        "STUN and HTTPS must report the same public IPv6"
    );
}

#[tokio::test]
async fn test_live_get_public_ips_both_families() {
    if skip_unless_ipv6_enabled("test_live_get_public_ips_both_families") {
        return;
    }

    let ftr = Ftr::new();
    let ips = ftr.get_public_ips().await;
    eprintln!("public IPs: v4={:?} v6={:?}", ips.v4, ips.v6);

    // Dual-stack machine (FTR_TEST_IPV6 asserts v6 works): both present.
    assert!(ips.v4.is_some(), "dual-stack machine should have public v4");
    assert!(ips.v6.is_some(), "dual-stack machine should have public v6");
    let v6 = ips.v6.expect("checked above");
    assert!(!v6.is_loopback());
    // A STUN-mapped v6 should be a global unicast, not link-local/ULA
    let seg = v6.segments();
    assert_ne!(seg[0] & 0xffc0, 0xfe80, "must not be link-local");
    assert_ne!(seg[0] & 0xfe00, 0xfc00, "must not be unique-local");
}

#[tokio::test]
async fn test_live_detect_isp_v6() {
    if skip_unless_ipv6_enabled("test_live_detect_isp_v6") {
        return;
    }

    let services = ftr::services::Services::new();
    let isp = ftr::public_ip::detect_isp_v6_stun_with_services(&services)
        .await
        .expect("v6 ISP detection should succeed on a dual-stack network");

    eprintln!(
        "v6 ISP: {} (AS{}) public_ip={} hostname={:?}",
        isp.name, isp.asn, isp.public_ip, isp.hostname
    );
    assert!(isp.public_ip.is_ipv6(), "public_ip must be an IPv6 address");
    assert_ne!(isp.asn, 0, "ISP ASN should be a real ASN");
    assert!(!isp.name.is_empty(), "ISP name should be populated");
}
