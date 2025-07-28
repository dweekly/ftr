# Test Coverage Expansion Plan for ftr

## Current State
- Current coverage: ~11% (from codecov)
- Unit tests: 44 passing tests
- Integration tests: 26 passing tests

## Areas Needing Test Coverage

### 1. Main Binary (`src/main.rs`)
Currently untested functions:
- [ ] `get_version()` - Version string generation
- [ ] `resolve_target()` - DNS resolution logic
- [ ] `display_json_results()` - JSON output formatting
- [ ] `display_text_results()` - Text output formatting with enrichment detection

### 2. ASN Module (`src/asn/`)
#### `asn/mod.rs`
- [ ] Module exports and re-exports

#### `asn/lookup.rs`
Current tests: Basic coverage for special IPs
Missing tests:
- [ ] DNS query formation (`form_dns_query`)
- [ ] Response parsing edge cases
- [ ] Network timeout handling
- [ ] Invalid DNS responses
- [ ] Concurrent lookup behavior
- [ ] Cache expiration

#### `asn/cache.rs`
Current tests: Basic cache operations
Missing tests:
- [ ] Cache size limits
- [ ] Concurrent access patterns
- [ ] TTL expiration behavior

### 3. DNS Module (`src/dns/`)
#### `dns/reverse.rs`
Current tests: Basic localhost and private IP
Missing tests:
- [ ] IPv6 address reverse lookups
- [ ] DNS resolution failures
- [ ] Timeout handling
- [ ] Invalid IP addresses
- [ ] Custom resolver configuration

### 4. Public IP Module (`src/public_ip/`)
#### `public_ip/providers.rs`
Current tests: Provider selection
Missing tests:
- [ ] HTTP request failures
- [ ] Invalid response formats
- [ ] Provider fallback mechanism
- [ ] Concurrent detection
- [ ] Network timeout scenarios
- [ ] Rate limiting responses

### 5. Traceroute Module (`src/traceroute/`)
#### `traceroute/config.rs`
Current tests: Basic builder and validation
Missing tests:
- [ ] Invalid configuration combinations
- [ ] Boundary value testing
- [ ] Default value behavior
- [ ] Builder method chaining

#### `traceroute/types.rs`
Current tests: Basic type functionality
Missing tests:
- [ ] Serialization/deserialization edge cases
- [ ] Display trait implementations
- [ ] Comparison operations

#### `traceroute/result.rs`
Current tests: Basic result operations
Missing tests:
- [ ] Empty result handling
- [ ] Large result sets
- [ ] Statistical calculations with edge cases

#### `traceroute/engine.rs`
Current tests: DNS resolution only
Missing tests:
- [ ] Full traceroute execution
- [ ] Probe timeout handling
- [ ] Destination reached detection
- [ ] Concurrent probe handling
- [ ] Socket errors
- [ ] Progress tracking

#### `traceroute/api.rs`
Current tests: Basic API usage
Missing tests:
- [ ] Error propagation
- [ ] Configuration validation
- [ ] Cancellation handling

### 6. Socket Module (`src/socket/`)
#### `socket/factory.rs`
Current tests: Basic factory operations
Missing tests:
- [ ] Platform-specific socket creation
- [ ] Permission error handling
- [ ] Socket option configuration

#### `socket/icmp_v4.rs`
Current tests: Basic ICMP operations
Missing tests:
- [ ] Packet parsing edge cases
- [ ] Malformed packet handling
- [ ] Buffer overflow protection
- [ ] Checksum validation

#### `socket/udp.rs`
Current tests: Basic UDP operations
Missing tests:
- [ ] Port configuration edge cases
- [ ] Response matching logic
- [ ] Timeout behavior

### 7. Integration Tests
Missing integration tests:
- [ ] Library API integration tests
- [ ] Multi-hop traceroute scenarios
- [ ] Error recovery scenarios
- [ ] Performance benchmarks
- [ ] Cross-platform behavior

## Testing Strategy

### Unit Test Guidelines
1. Each public function should have at least one test
2. Error paths should be tested explicitly
3. Edge cases and boundary values should be covered
4. Concurrent access should be tested where applicable

### Integration Test Guidelines
1. Test the complete library API workflow
2. Test error scenarios end-to-end
3. Test performance characteristics
4. Test platform-specific behaviors

### Mock Strategy
1. Mock external services (DNS, HTTP)
2. Mock socket operations for predictable testing
3. Use property-based testing for complex inputs

## Implementation Priority

### High Priority (Core Functionality)
1. Traceroute engine tests
2. Socket operation tests
3. Library API integration tests
4. Main.rs display functions

### Medium Priority (Supporting Features)
1. ASN lookup error cases
2. DNS resolution edge cases
3. Public IP detection failures
4. Configuration validation

### Low Priority (Nice to Have)
1. Performance benchmarks
2. Property-based tests
3. Stress tests
4. Fuzz testing

## Tools and Techniques

### Recommended Testing Tools
- `mockall` - For mocking external dependencies
- `proptest` - For property-based testing
- `criterion` - For benchmarking
- `test-case` - For parameterized tests
- `serial_test` - For tests requiring serialization

### Coverage Goals
- Short term: 50% coverage
- Medium term: 70% coverage
- Long term: 85%+ coverage

## Example Test Implementations

### Example 1: Testing Display Functions
```rust
#[cfg(test)]
mod display_tests {
    use super::*;
    
    #[test]
    fn test_display_json_results() {
        let result = create_test_result();
        let json_output = display_json_results(result).unwrap();
        assert!(json_output.contains("\"version\""));
        assert!(json_output.contains("\"hops\""));
    }
    
    #[test]
    fn test_display_text_with_enrichment() {
        // Test with enrichment enabled
        let result = create_enriched_result();
        // Capture stdout and verify format
    }
}
```

### Example 2: Testing Engine with Mocks
```rust
#[cfg(test)]
mod engine_tests {
    use super::*;
    use mockall::mock;
    
    mock! {
        TestSocket {}
        impl ProbeSocket for TestSocket {
            // Mock methods
        }
    }
    
    #[tokio::test]
    async fn test_engine_timeout_handling() {
        let mock_socket = MockTestSocket::new();
        // Configure mock expectations
        let engine = TracerouteEngine::new(config, Box::new(mock_socket));
        // Test timeout scenarios
    }
}
```

### Example 3: Integration Test
```rust
#[tokio::test]
async fn test_library_api_complete_flow() {
    let config = TracerouteConfigBuilder::new()
        .target("127.0.0.1")
        .max_hops(3)
        .build()
        .unwrap();
    
    let result = trace_with_config(config).await;
    assert!(result.is_ok());
    
    let result = result.unwrap();
    assert_eq!(result.target_ip, "127.0.0.1".parse().unwrap());
    assert!(!result.hops.is_empty());
}
```

## Next Steps
1. Set up test infrastructure (mocking framework, test utilities)
2. Create test fixtures and helpers
3. Implement high-priority tests first
4. Set up CI to track coverage metrics
5. Add coverage badges to README