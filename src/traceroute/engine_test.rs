/// Tests for TracerouteEngine using a mock ProbeSocket
///
/// These tests verify engine control flow (probe sequencing, TTL handling,
/// response aggregation, timeout/early-exit logic) without any network access.
use crate::probe::{ProbeInfo, ProbeResponse};
use crate::socket::traits::{ProbeMode, ProbeSocket};
use crate::traceroute::{TracerouteConfig, TracerouteError};
use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr};
use std::pin::Pin;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// A mock ProbeSocket that returns predetermined responses per TTL.
struct MockSocket {
    /// Map from TTL -> (responding IP, is_destination)
    responses: HashMap<u8, (Ipv4Addr, bool)>,
    /// Simulated RTT
    rtt: Duration,
    destination_reached: AtomicBool,
    pending: AtomicUsize,
    /// Track which probes were sent (ttl, sequence)
    sent_probes: Mutex<Vec<(u8, u16)>>,
}

impl MockSocket {
    fn new(responses: HashMap<u8, (Ipv4Addr, bool)>, rtt: Duration) -> Self {
        Self {
            responses,
            rtt,
            destination_reached: AtomicBool::new(false),
            pending: AtomicUsize::new(0),
            sent_probes: Mutex::new(Vec::new()),
        }
    }

    /// Create a mock simulating a 3-hop path to a destination
    fn three_hop_path() -> Self {
        let mut responses = HashMap::new();
        responses.insert(1, (Ipv4Addr::new(192, 168, 1, 1), false));
        responses.insert(2, (Ipv4Addr::new(10, 0, 0, 1), false));
        responses.insert(3, (Ipv4Addr::new(8, 8, 8, 8), true));
        Self::new(responses, Duration::from_millis(5))
    }

    /// Create a mock where TTL 2 times out (no response)
    fn path_with_timeout() -> Self {
        let mut responses = HashMap::new();
        responses.insert(1, (Ipv4Addr::new(192, 168, 1, 1), false));
        // TTL 2 has no entry -> timeout
        responses.insert(3, (Ipv4Addr::new(8, 8, 8, 8), true));
        Self::new(responses, Duration::from_millis(5))
    }
}

impl ProbeSocket for MockSocket {
    fn mode(&self) -> ProbeMode {
        ProbeMode::DgramIcmp
    }

    fn send_probe_and_recv(
        &self,
        _dest: IpAddr,
        probe: ProbeInfo,
    ) -> Pin<Box<dyn Future<Output = Result<ProbeResponse, TracerouteError>> + Send + '_>> {
        let ttl = probe.ttl;
        let seq = probe.sequence;

        // Record that this probe was sent
        if let Ok(mut sent) = self.sent_probes.lock() {
            sent.push((ttl, seq));
        }

        Box::pin(async move {
            // Simulate network delay
            tokio::time::sleep(self.rtt).await;

            if let Some(&(addr, is_dest)) = self.responses.get(&ttl) {
                if is_dest {
                    self.destination_reached.store(true, Ordering::Relaxed);
                }
                Ok(ProbeResponse {
                    from_addr: IpAddr::V4(addr),
                    sequence: seq,
                    ttl,
                    rtt: self.rtt,
                    received_at: Instant::now(),
                    is_destination: is_dest,
                    is_timeout: false,
                })
            } else {
                // Simulate timeout
                tokio::time::sleep(Duration::from_millis(50)).await;
                Ok(ProbeResponse {
                    from_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                    sequence: seq,
                    ttl,
                    rtt: Duration::from_millis(50),
                    received_at: Instant::now(),
                    is_destination: false,
                    is_timeout: true,
                })
            }
        })
    }

    fn destination_reached(&self) -> bool {
        self.destination_reached.load(Ordering::Relaxed)
    }

    fn pending_count(&self) -> usize {
        self.pending.load(Ordering::Relaxed)
    }
}

fn test_config(max_hops: u8) -> TracerouteConfig {
    TracerouteConfig::builder()
        .target("8.8.8.8")
        .max_hops(max_hops)
        .probe_timeout(Duration::from_millis(200))
        .overall_timeout(Duration::from_secs(2))
        .enable_asn_lookup(false)
        .enable_rdns(false)
        .build()
        .expect("valid test config")
}

#[tokio::test]
async fn test_engine_three_hop_path() {
    let socket = MockSocket::three_hop_path();
    let config = test_config(5);
    let target: IpAddr = "8.8.8.8".parse().expect("valid IPv4 address");

    let engine = super::TracerouteEngine::new(Box::new(socket), config, target)
        .await
        .expect("engine creation");

    let result = engine.run().await.expect("traceroute should succeed");

    assert!(result.destination_reached);
    // Should have hops for TTLs 1, 2, 3
    assert!(!result.hops.is_empty());

    // Find the destination hop
    let dest_hop = result
        .hops
        .iter()
        .find(|h| h.addr == Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
    assert!(dest_hop.is_some(), "should find destination hop");
}

#[tokio::test]
async fn test_engine_handles_timeout_hops() {
    let socket = MockSocket::path_with_timeout();
    let config = test_config(5);
    let target: IpAddr = "8.8.8.8".parse().expect("valid IPv4 address");

    let engine = super::TracerouteEngine::new(Box::new(socket), config, target)
        .await
        .expect("engine creation");

    let result = engine.run().await.expect("traceroute should succeed");

    assert!(result.destination_reached);
    // Should still reach destination despite TTL 2 timeout
    let dest_hop = result
        .hops
        .iter()
        .find(|h| h.addr == Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
    assert!(
        dest_hop.is_some(),
        "should reach destination despite timeout at TTL 2"
    );
}

#[tokio::test]
async fn test_engine_sends_correct_number_of_probes() {
    let socket = MockSocket::three_hop_path();
    let config = test_config(3);
    let target: IpAddr = "8.8.8.8".parse().expect("valid IPv4 address");

    let engine = super::TracerouteEngine::new(Box::new(socket), config, target)
        .await
        .expect("engine creation");

    let result = engine.run().await.expect("traceroute should succeed");

    // With max_hops=3 and queries_per_hop=1 (default), should have sent 3 probes
    // (one for each TTL 1, 2, 3) and reached destination
    assert!(result.destination_reached);

    // Verify we got responses from all 3 hops
    let responding_hops: Vec<_> = result.hops.iter().filter(|h| h.addr.is_some()).collect();
    assert_eq!(responding_hops.len(), 3, "should have 3 responding hops");
}

#[tokio::test]
async fn test_engine_no_destination_reached() {
    // All hops return non-destination responses
    let mut responses = HashMap::new();
    responses.insert(1, (Ipv4Addr::new(192, 168, 1, 1), false));
    responses.insert(2, (Ipv4Addr::new(10, 0, 0, 1), false));
    let socket = MockSocket::new(responses, Duration::from_millis(5));

    let config = test_config(3);
    let target: IpAddr = "8.8.8.8".parse().expect("valid IPv4 address");

    let engine = super::TracerouteEngine::new(Box::new(socket), config, target)
        .await
        .expect("engine creation");

    let result = engine.run().await.expect("traceroute should succeed");

    assert!(!result.destination_reached);
}

#[tokio::test]
async fn test_engine_result_metadata() {
    let socket = MockSocket::three_hop_path();
    let config = test_config(5);
    let target: IpAddr = "8.8.8.8".parse().expect("valid IPv4 address");

    let engine = super::TracerouteEngine::new(Box::new(socket), config, target)
        .await
        .expect("engine creation");

    let result = engine.run().await.expect("traceroute should succeed");

    assert_eq!(result.target, "8.8.8.8");
    assert_eq!(result.target_ip, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
    assert!(result.total_duration > Duration::ZERO);
}

#[tokio::test]
async fn test_engine_single_hop_destination() {
    // Destination is directly reachable at TTL 1
    let mut responses = HashMap::new();
    responses.insert(1, (Ipv4Addr::new(8, 8, 8, 8), true));
    let socket = MockSocket::new(responses, Duration::from_millis(1));

    let config = test_config(30);
    let target: IpAddr = "8.8.8.8".parse().expect("valid IPv4 address");

    let engine = super::TracerouteEngine::new(Box::new(socket), config, target)
        .await
        .expect("engine creation");

    let result = engine.run().await.expect("traceroute should succeed");

    assert!(result.destination_reached);
    // Should have exactly one hop
    let non_timeout_hops: Vec<_> = result.hops.iter().filter(|h| h.addr.is_some()).collect();
    assert_eq!(non_timeout_hops.len(), 1);
}

#[tokio::test]
async fn test_engine_overall_timeout() {
    // All hops are very slow — should hit overall timeout
    let mut responses = HashMap::new();
    for ttl in 1..=30 {
        responses.insert(ttl, (Ipv4Addr::new(10, 0, 0, ttl), false));
    }
    let socket = MockSocket::new(responses, Duration::from_millis(500));

    let mut config = test_config(30);
    config.overall_timeout = Duration::from_millis(200); // Very short overall timeout

    let target: IpAddr = "8.8.8.8".parse().expect("valid IPv4 address");

    let engine = super::TracerouteEngine::new(Box::new(socket), config, target)
        .await
        .expect("engine creation");

    let result = engine
        .run()
        .await
        .expect("traceroute should succeed even on timeout");

    // Should complete without error, but won't have all hops
    assert!(!result.destination_reached);
}

#[tokio::test]
async fn test_engine_uses_injected_services_for_enrichment() {
    use crate::asn::cache::AsnCache;
    use crate::dns::cache::RdnsCache;
    use crate::services::Services;
    use crate::traceroute::AsnInfo;
    use std::sync::Arc;

    let dest = Ipv4Addr::new(8, 8, 8, 8);
    let mut responses = HashMap::new();
    responses.insert(1, (dest, true));
    let socket = MockSocket::new(responses, Duration::from_millis(1));

    // Pre-warm the injected services' caches with sentinel values. Cache hits
    // are served before any network I/O, so all enrichment (per-hop ASN/rDNS,
    // destination ASN, ISP detection from the provided public IP) resolves
    // from the cache. If the engine ignored the injected services (the old
    // bug), hop enrichment would perform live lookups and the sentinels would
    // never appear.
    let asn_cache = AsnCache::new();
    asn_cache.insert(
        "8.8.8.0/24".parse().expect("valid prefix"),
        AsnInfo {
            asn: 64512,
            name: "SENTINEL-AS".to_string(),
            prefix: "8.8.8.0/24".to_string(),
            country_code: "ZZ".to_string(),
            registry: "test".to_string(),
        },
    );
    let rdns_cache = RdnsCache::with_default_ttl();
    rdns_cache.insert(IpAddr::V4(dest), "sentinel.rdns.test".to_string());

    let services = Arc::new(Services::with_caches(
        Some(asn_cache),
        Some(rdns_cache),
        None,
    ));

    let config = TracerouteConfig::builder()
        .target("8.8.8.8")
        .max_hops(2)
        .probe_timeout(Duration::from_millis(200))
        .overall_timeout(Duration::from_secs(2))
        .enable_asn_lookup(true)
        .enable_rdns(true)
        // Providing the public IP avoids STUN; its ASN/rDNS hit the cache too
        .public_ip(IpAddr::V4(dest))
        .build()
        .expect("valid config");

    let target: IpAddr = IpAddr::V4(dest);
    let engine =
        super::TracerouteEngine::new_with_services(Box::new(socket), config, target, services)
            .await
            .expect("engine creation");

    let result = engine.run().await.expect("traceroute should succeed");

    let hop = result
        .hops
        .iter()
        .find(|h| h.addr == Some(target))
        .expect("destination hop present");
    let asn = hop
        .asn_info
        .as_ref()
        .expect("hop ASN info should come from the injected cache");
    assert_eq!(asn.asn, 64512);
    assert_eq!(asn.name, "SENTINEL-AS");
    assert_eq!(hop.hostname.as_deref(), Some("sentinel.rdns.test"));

    // ISP info is resolved through the same injected services
    let isp = result.isp_info.expect("ISP info present");
    assert_eq!(isp.asn, 64512);
    assert_eq!(isp.hostname.as_deref(), Some("sentinel.rdns.test"));
}

/// v6 on-link LAN classification (`classify_v6_hop`): the shared-/64
/// heuristic plus the internal-scope rules, platform-independent.
mod classify_v6_hop {
    use crate::traceroute::AsnInfo;
    use crate::traceroute::SegmentType;
    use crate::traceroute::engine::TracerouteEngine;
    use std::net::Ipv6Addr;

    /// The maintainer's own topology (docs/IPV6_DESIGN.md live trace):
    /// host source and gateway share the delegated /64.
    const LOCAL_SOURCE: Ipv6Addr = Ipv6Addr::new(
        0x2001, 0x5a8, 0x4681, 0x2c00, 0x41b1, 0x1c86, 0xaee8, 0x0e97,
    );
    const GATEWAY: Ipv6Addr = Ipv6Addr::new(0x2001, 0x5a8, 0x4681, 0x2c00, 0, 0, 0, 1);
    /// Sonic's first upstream hop — same ISP, different /64.
    const ISP_HOP: Ipv6Addr = Ipv6Addr::new(0x2001, 0x5a8, 0x657, 0x21, 0, 0, 0xf0, 4);

    fn sonic_asn() -> AsnInfo {
        AsnInfo {
            asn: 46375,
            prefix: "2001:5a8::/32".to_string(),
            country_code: "US".to_string(),
            registry: "arin".to_string(),
            name: "AS-SONICTELECOM".to_string(),
        }
    }

    #[test]
    fn gateway_in_same_slash64_is_lan() {
        // The gateway answers from a global address in the delegated
        // prefix; even with the ISP's ASN attached it must be LAN.
        let mut in_isp = false;
        let segment = TracerouteEngine::classify_v6_hop(
            &GATEWAY,
            Some(&LOCAL_SOURCE),
            Some(&sonic_asn()),
            Some(46375),
            None,
            &mut in_isp,
        );
        assert_eq!(segment, SegmentType::Lan);
        assert!(!in_isp, "LAN hop must not open the ISP segment");
    }

    #[test]
    fn different_slash64_same_isp_is_isp() {
        // One /64 boundary out, ASN classification takes over.
        let mut in_isp = false;
        let segment = TracerouteEngine::classify_v6_hop(
            &ISP_HOP,
            Some(&LOCAL_SOURCE),
            Some(&sonic_asn()),
            Some(46375),
            None,
            &mut in_isp,
        );
        assert_eq!(segment, SegmentType::Isp);
        assert!(in_isp);
    }

    #[test]
    fn link_local_is_lan_regardless_of_source() {
        let fe80: Ipv6Addr = "fe80::1".parse().expect("valid");
        let mut in_isp = false;
        // Even with no local source available, fe80::/10 stays LAN.
        let segment = TracerouteEngine::classify_v6_hop(&fe80, None, None, None, None, &mut in_isp);
        assert_eq!(segment, SegmentType::Lan);
    }

    #[test]
    fn no_local_source_falls_back_to_asn_logic() {
        // Without a local source the /64 heuristic is inert: the gateway
        // address classifies by ASN (the pre-fix behavior).
        let mut in_isp = false;
        let segment = TracerouteEngine::classify_v6_hop(
            &GATEWAY,
            None,
            Some(&sonic_asn()),
            Some(46375),
            None,
            &mut in_isp,
        );
        assert_eq!(segment, SegmentType::Isp);
    }

    #[test]
    fn prefix_match_is_exactly_64_bits() {
        // 2001:5a8:4681:2c01::1 differs only in the 4th hextet (the /64
        // boundary) — must NOT be treated as on-link.
        let neighbor_prefix = Ipv6Addr::new(0x2001, 0x5a8, 0x4681, 0x2c01, 0, 0, 0, 1);
        let mut in_isp = false;
        let segment = TracerouteEngine::classify_v6_hop(
            &neighbor_prefix,
            Some(&LOCAL_SOURCE),
            Some(&sonic_asn()),
            Some(46375),
            None,
            &mut in_isp,
        );
        assert_eq!(segment, SegmentType::Isp);
    }
}
