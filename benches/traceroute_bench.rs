//! Criterion benchmarks for traceroute performance (localhost and remote,
//! with and without ASN/rDNS enrichment).

use criterion::{Criterion, criterion_main};
use ftr::{TracerouteConfig, trace_with_config};
use std::hint::black_box;
use std::time::Duration;

fn benchmark_traceroute_local(c: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");

    c.bench_function("traceroute_localhost", |b| {
        b.iter(|| {
            runtime.block_on(async {
                let config = TracerouteConfig::builder()
                    .target("127.0.0.1")
                    .max_hops(5)
                    .probe_timeout(Duration::from_millis(100))
                    .overall_timeout(Duration::from_millis(500))
                    .enable_asn_lookup(false)
                    .enable_rdns(false)
                    .build()
                    .expect("failed to build traceroute config");

                let _ = trace_with_config(black_box(config)).await;
            })
        })
    });
}

fn benchmark_traceroute_with_enrichment(c: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");

    c.bench_function("traceroute_8.8.8.8_enriched", |b| {
        b.iter(|| {
            runtime.block_on(async {
                let config = TracerouteConfig::builder()
                    .target("8.8.8.8")
                    .max_hops(10)
                    .probe_timeout(Duration::from_millis(500))
                    .overall_timeout(Duration::from_secs(2))
                    .enable_asn_lookup(true)
                    .enable_rdns(true)
                    .build()
                    .expect("failed to build traceroute config");

                let _ = trace_with_config(black_box(config)).await;
            })
        })
    });
}

fn benchmark_traceroute_no_enrichment(c: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");

    c.bench_function("traceroute_8.8.8.8_raw", |b| {
        b.iter(|| {
            runtime.block_on(async {
                let config = TracerouteConfig::builder()
                    .target("8.8.8.8")
                    .max_hops(10)
                    .probe_timeout(Duration::from_millis(500))
                    .overall_timeout(Duration::from_secs(2))
                    .enable_asn_lookup(false)
                    .enable_rdns(false)
                    .build()
                    .expect("failed to build traceroute config");

                let _ = trace_with_config(black_box(config)).await;
            })
        })
    });
}

// criterion_group! expands to an undocumented `pub fn`, which trips the
// missing_docs lint. Housing it in a private module keeps the generated
// function out of the crate's public surface so no doc (or allow) is needed.
mod groups {
    use super::{
        benchmark_traceroute_local, benchmark_traceroute_no_enrichment,
        benchmark_traceroute_with_enrichment,
    };
    use criterion::criterion_group;

    criterion_group!(
        benches,
        benchmark_traceroute_local,
        benchmark_traceroute_no_enrichment,
        benchmark_traceroute_with_enrichment
    );
}
criterion_main!(groups::benches);
