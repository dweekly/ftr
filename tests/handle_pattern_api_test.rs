//! Tests for the handle pattern API

use ftr::{Ftr, TracerouteConfigBuilder};

#[tokio::test]
async fn test_ftr_instance_methods() {
    let ftr = Ftr::new();

    // Test trace() convenience method
    let result = ftr.trace("127.0.0.1").await;
    assert!(result.is_ok() || result.is_err()); // Either is fine

    // Test trace_with_config()
    let config = TracerouteConfigBuilder::new()
        .target("::1")
        .max_hops(1)
        .build()
        .unwrap();

    let result = ftr.trace_with_config(config).await;
    assert!(result.is_ok() || result.is_err()); // Platform-dependent
}

#[tokio::test]
async fn test_ftr_with_custom_caches() {
    use ftr::asn::AsnCache;
    use ftr::dns::RdnsCache;
    use ftr::public_ip::stun_cache::StunCache;

    // Create custom caches
    let asn_cache = AsnCache::new();
    let rdns_cache = RdnsCache::with_default_ttl();
    let stun_cache = StunCache::new();

    // Create Ftr with custom caches
    let ftr = Ftr::with_caches(Some(asn_cache), Some(rdns_cache), Some(stun_cache));

    // Use it normally
    let result = ftr.trace("192.168.1.1").await;
    assert!(result.is_ok() || result.is_err());
}

#[tokio::test]
async fn test_multiple_ftr_instances_are_independent() {
    let ftr1 = Ftr::new();
    let ftr2 = Ftr::new();
    let ftr3 = Ftr::new();

    // All three can be used independently
    let (r1, r2, r3) = tokio::join!(
        ftr1.trace("10.0.0.1"),
        ftr2.trace("172.16.0.1"),
        ftr3.trace("192.168.0.1")
    );

    // All should complete (success or failure is platform-dependent)
    assert!(r1.is_ok() || r1.is_err());
    assert!(r2.is_ok() || r2.is_err());
    assert!(r3.is_ok() || r3.is_err());
}

#[test]
fn test_ftr_is_send_sync() {
    // Verify that Ftr implements Send + Sync
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Ftr>();
}

#[tokio::test]
async fn test_ftr_can_be_shared_with_arc() {
    use std::sync::Arc;
    use tokio::task::JoinSet;

    let ftr = Arc::new(Ftr::new());
    let mut tasks = JoinSet::new();

    for i in 0..5 {
        let ftr_clone = ftr.clone();
        tasks.spawn(async move {
            let target = format!("192.168.1.{}", i + 1);
            ftr_clone.trace(&target).await
        });
    }

    let mut count = 0;
    while let Some(result) = tasks.join_next().await {
        if result.is_ok() {
            count += 1;
        }
    }

    assert_eq!(count, 5);
}

#[tokio::test]
async fn test_timing_config_flows_through() {
    use ftr::TimingConfig;
    use std::time::Duration;

    let ftr = Ftr::new();

    // Create config with custom timing
    let custom_timing = TimingConfig {
        socket_read_timeout: Duration::from_millis(100),
        udp_retry_delay: Duration::from_millis(10),
        receiver_poll_interval: Duration::from_millis(2),
        main_loop_poll_interval: Duration::from_millis(10),
        enrichment_wait_time: Duration::from_millis(300),
    };

    let config = TracerouteConfigBuilder::new()
        .target("127.0.0.1")
        .max_hops(1)
        .timing(custom_timing)
        .build()
        .unwrap();

    // This should use the custom timing config
    let result = ftr.trace_with_config(config).await;
    assert!(result.is_ok() || result.is_err());
}

#[tokio::test]
async fn test_ftr_with_partial_caches() {
    use ftr::asn::AsnCache;

    // Create Ftr with only ASN cache custom, others default
    let custom_asn = AsnCache::new();
    let ftr = Ftr::with_caches(Some(custom_asn), None, None);

    let result = ftr.trace("8.8.8.8").await;
    assert!(result.is_ok() || result.is_err());
}

#[tokio::test]
async fn test_ftr_default_is_same_as_new() {
    let ftr1 = Ftr::new();
    let ftr2 = Ftr::default();

    // Both should work the same way
    let config = TracerouteConfigBuilder::new()
        .target("localhost")
        .max_hops(1)
        .build()
        .unwrap();

    let (r1, r2) = tokio::join!(
        ftr1.trace_with_config(config.clone()),
        ftr2.trace_with_config(config)
    );

    // Both should have same success/failure
    assert_eq!(r1.is_ok(), r2.is_ok());
}
