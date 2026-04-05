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
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;
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
    let target: IpAddr = "8.8.8.8".parse().unwrap();

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
    let target: IpAddr = "8.8.8.8".parse().unwrap();

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
    let target: IpAddr = "8.8.8.8".parse().unwrap();

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
    let target: IpAddr = "8.8.8.8".parse().unwrap();

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
    let target: IpAddr = "8.8.8.8".parse().unwrap();

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
    let target: IpAddr = "8.8.8.8".parse().unwrap();

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

    let target: IpAddr = "8.8.8.8".parse().unwrap();

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
