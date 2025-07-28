# Quick Wins for Expanding Test Coverage

## Immediate Actions (High Impact, Low Effort)

### 1. Add Tests for Display Functions in main.rs
- Test `get_version()` function
- Test `display_json_results()` with various result types
- Test `display_text_results()` with and without enrichment
- Test `resolve_target()` with IPs and hostnames

### 2. Mock-based Engine Tests
- Create mock socket implementation
- Test timeout scenarios
- Test destination reached detection
- Test silent hop handling
- Test concurrent probe handling

### 3. Property-based Tests for Parsers
```rust
use proptest::prelude::*;

proptest! {
    #[test]
    fn test_parse_cidr_roundtrip(
        a in 0u8..=255,
        b in 0u8..=255,
        c in 0u8..=255,
        d in 0u8..=255,
        prefix in 0u8..=32
    ) {
        let cidr = format!("{}.{}.{}.{}/{}", a, b, c, d, prefix);
        if let Some((network, parsed_prefix)) = parse_cidr(&cidr) {
            assert_eq!(parsed_prefix, prefix);
        }
    }
}
```

### 4. Error Path Testing
- Test all error conditions in config validation
- Test socket creation failures
- Test DNS resolution failures
- Test HTTP request failures in public IP detection

### 5. Integration Tests for Library API
```rust
#[tokio::test]
async fn test_trace_localhost() {
    let result = ftr::trace("127.0.0.1").await;
    assert!(result.is_ok());
    let result = result.unwrap();
    assert!(result.destination_reached);
    assert_eq!(result.hops.len(), 1);
}

#[tokio::test]
async fn test_trace_with_custom_config() {
    let config = ftr::TracerouteConfigBuilder::new()
        .target("localhost")
        .max_hops(3)
        .queries_per_hop(2)
        .build()
        .unwrap();
    
    let result = ftr::trace_with_config(config).await;
    assert!(result.is_ok());
}
```

## Test Data Fixtures

### 1. Create Common Test Data
```rust
mod fixtures {
    use super::*;
    
    pub fn create_test_hop(ttl: u8) -> ClassifiedHopInfo {
        ClassifiedHopInfo {
            ttl,
            segment: SegmentType::Unknown,
            hostname: None,
            addr: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, ttl))),
            asn_info: None,
            rtt: Some(Duration::from_millis(ttl as u64 * 5)),
        }
    }
    
    pub fn create_test_result() -> TracerouteResult {
        TracerouteResult {
            target: "test.example".to_string(),
            target_ip: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            hops: vec![create_test_hop(1), create_test_hop(2)],
            isp_info: None,
            protocol_used: ProbeProtocol::Icmp,
            socket_mode_used: SocketMode::Raw,
            destination_reached: true,
            total_duration: Duration::from_millis(100),
        }
    }
}
```

## Platform-specific Test Organization

### 1. Use Conditional Compilation
```rust
#[cfg(target_os = "linux")]
mod linux_tests {
    #[test]
    fn test_linux_specific_socket() {
        // Linux-specific tests
    }
}

#[cfg(target_os = "windows")]
mod windows_tests {
    #[test]
    fn test_windows_socket() {
        // Windows-specific tests
    }
}
```

### 2. Skip Tests When Appropriate
```rust
#[test]
#[ignore = "requires root privileges"]
fn test_raw_socket_creation() {
    // Test that requires root
}

#[test]
#[cfg_attr(not(feature = "online-tests"), ignore)]
fn test_real_dns_lookup() {
    // Test that requires network access
}
```

## Benchmark Tests

### 1. Add Performance Benchmarks
```rust
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn benchmark_asn_lookup(c: &mut Criterion) {
    c.bench_function("asn_lookup_cached", |b| {
        b.iter(|| {
            lookup_asn(black_box(Ipv4Addr::new(8, 8, 8, 8)), None)
        })
    });
}

criterion_group!(benches, benchmark_asn_lookup);
criterion_main!(benches);
```

## CI Integration

### 1. Add Coverage to CI
```yaml
- name: Run tests with coverage
  run: |
    cargo install cargo-tarpaulin
    cargo tarpaulin --out Xml --all-features --workspace

- name: Upload coverage
  uses: codecov/codecov-action@v3
  with:
    files: ./cobertura.xml
```

### 2. Add Test Matrix
```yaml
strategy:
  matrix:
    os: [ubuntu-latest, windows-latest, macos-latest]
    rust: [stable, nightly]
```

## Testing Best Practices

1. **Test One Thing**: Each test should verify one specific behavior
2. **Clear Names**: Use descriptive test names that explain what's being tested
3. **Arrange-Act-Assert**: Structure tests clearly
4. **Test Edge Cases**: Empty inputs, maximum values, invalid data
5. **Mock External Dependencies**: DNS, HTTP, system calls
6. **Use Test Utilities**: Create helper functions for common test setup

## Measuring Progress

1. Run coverage locally: `cargo tarpaulin --out Html`
2. Set coverage targets:
   - 50% by end of week 1
   - 70% by end of week 2
   - 85% by end of month
3. Focus on critical paths first
4. Add tests with every bug fix
5. Require tests in PR reviews