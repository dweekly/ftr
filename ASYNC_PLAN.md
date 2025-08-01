# Async Traceroute Implementation Plan

## Overview

This document outlines the plan to migrate ftr from a synchronous, polling-based architecture to a fully asynchronous implementation using Tokio. This will eliminate the current 200ms+ delays in response processing while maintaining non-administrator privileges across all platforms.

## Problem Statement

Current issues:
1. **Windows event delays**: Responses with 3ms RTT take 200ms+ to be processed due to polling intervals
2. **Synchronous enrichment**: DNS and ASN lookups block the main flow
3. **Platform-specific code**: Different implementations for each OS with varying performance
4. **Polling overhead**: Constant checking for responses instead of being notified

## Goals

1. **Immediate response processing**: < 1ms delay from packet arrival to processing
2. **Preserve non-admin usage**: Continue working without elevated privileges
3. **Unified codebase**: Single async implementation for all platforms
4. **Parallel enrichment**: DNS and ASN lookups happen concurrently
5. **Future extensibility**: Easy to add IPv6, TCP, HTTP/3 traceroute modes

## Architecture Design

### Core Components

```rust
// 1. Async Socket Trait
#[async_trait]
pub trait AsyncProbeSocket: Send + Sync {
    fn mode(&self) -> ProbeMode;
    async fn send_probe(&self, dest: IpAddr, probe: ProbeInfo) -> Result<()>;
    async fn recv_response(&self) -> Result<ProbeResponse>;
    fn destination_reached(&self) -> bool;
}

// 2. Platform Implementations
pub struct AsyncDgramIcmpSocket { /* Linux/macOS DGRAM ICMP */ }
pub struct AsyncWindowsIcmpSocket { /* Windows IcmpSendEcho2 */ }
pub struct AsyncUdpSocket { /* Linux UDP with IP_RECVERR */ }
pub struct AsyncRawIcmpSocket { /* Fallback raw socket */ }

// 3. Async Traceroute Engine
pub struct AsyncTracerouteEngine {
    socket: Arc<Box<dyn AsyncProbeSocket>>,
    config: TracerouteConfig,
    enrichment_service: Arc<EnrichmentService>,
}

// 4. Enrichment Service
pub struct EnrichmentService {
    dns_resolver: Arc<TokioAsyncResolver>,
    asn_cache: Arc<RwLock<HashMap<Ipv4Addr, AsnInfo>>>,
}
```

### Key Implementation Details

#### Windows Async ICMP

For Windows, we'll wrap IcmpSendEcho2 with Tokio's async primitives:

```rust
impl AsyncWindowsIcmpSocket {
    async fn send_probe(&self, dest: IpAddr, probe: ProbeInfo) -> Result<()> {
        let event = create_event();
        
        // Send ICMP request
        IcmpSendEcho2(handle, event, ...);
        
        // Convert Windows event to Tokio async
        let async_event = AsyncEvent::from_handle(event);
        
        // Store pending probe
        self.pending_probes.insert(sequence, PendingProbe { 
            event: async_event,
            probe_info,
            ...
        });
        
        Ok(())
    }
    
    async fn wait_for_response(&self, sequence: u16) -> Result<ProbeResponse> {
        let pending = self.pending_probes.get(&sequence).unwrap();
        
        // This will wake up IMMEDIATELY when Windows signals the event
        pending.event.wait().await;
        
        // Process the response with 0ms delay
        self.process_response(pending)
    }
}
```

#### Linux/macOS Async Sockets

```rust
impl AsyncDgramIcmpSocket {
    async fn new() -> Result<Self> {
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Protocol::ICMPV4)?;
        socket.bind(&"0.0.0.0:0".parse()?)?;
        
        // Convert to Tokio async socket
        let async_socket = TokioSocket::from_std(socket.into())?;
        
        Ok(Self { socket: async_socket })
    }
    
    async fn recv_response(&self) -> Result<ProbeResponse> {
        let mut buf = [0u8; 512];
        
        // This will wake up IMMEDIATELY when packet arrives
        let (size, from) = self.socket.recv_from(&mut buf).await?;
        
        // Parse ICMP response
        self.parse_response(&buf[..size], from)
    }
}
```

#### Async Traceroute Engine

```rust
impl AsyncTracerouteEngine {
    pub async fn run(&self) -> Result<TracerouteResult> {
        let start = Instant::now();
        
        // 1. Start enrichment tasks in background
        let enrichment_handle = tokio::spawn(
            self.enrichment_service.start_background_enrichment()
        );
        
        // 2. Send all probes concurrently
        let mut probe_tasks = FuturesUnordered::new();
        
        for ttl in self.config.start_ttl..=self.config.max_hops {
            for query in 0..self.config.queries_per_hop {
                let probe_future = self.send_probe_and_wait(ttl, query);
                probe_tasks.push(probe_future);
            }
        }
        
        // 3. Collect responses as they arrive - IMMEDIATELY
        let mut responses = Vec::new();
        let timeout = tokio::time::sleep(self.config.overall_timeout);
        tokio::pin!(timeout);
        
        loop {
            tokio::select! {
                Some(response) = probe_tasks.next() => {
                    if let Ok(resp) = response {
                        // Queue for enrichment
                        self.enrichment_service.enqueue(resp.from_addr).await;
                        
                        responses.push(resp);
                        
                        if self.should_stop(&responses) {
                            break;
                        }
                    }
                }
                _ = &mut timeout => {
                    break;
                }
            }
        }
        
        // 4. Wait for enrichment to complete
        let enrichment_results = enrichment_handle.await?;
        
        // 5. Build final result
        self.build_result(responses, enrichment_results, start.elapsed())
    }
}
```

#### Parallel Enrichment Service

```rust
impl EnrichmentService {
    async fn enqueue(&self, addr: IpAddr) {
        if self.seen_addresses.insert(addr) {
            self.enrichment_queue.send(addr).await.ok();
        }
    }
    
    async fn start_background_enrichment(&self) {
        let mut enrichment_futures = FuturesUnordered::new();
        
        while let Some(addr) = self.enrichment_queue.recv().await {
            // Spawn parallel DNS and ASN lookups
            let dns_future = self.dns_resolver.reverse_lookup(addr);
            let asn_future = self.lookup_asn(addr);
            
            enrichment_futures.push(async move {
                let (dns, asn) = tokio::join!(dns_future, asn_future);
                (addr, dns, asn)
            });
        }
        
        // Collect all enrichment results
        while let Some((addr, dns, asn)) = enrichment_futures.next().await {
            self.results.insert(addr, EnrichmentResult { dns, asn });
        }
    }
}
```

## Implementation Phases

### Phase 1: Core Async Infrastructure (Week 1) ✅
1. ✅ Add tokio dependency with Windows, macOS, Linux features
2. ✅ Create AsyncProbeSocket trait
3. ✅ Implement AsyncEvent wrapper for Windows events
4. ✅ Set up async runtime in main.rs

### Phase 2: Platform Implementations (Week 2) 
1. ✅ AsyncWindowsIcmpSocket using IcmpSendEcho2 + async events
2. ✅ AsyncDgramIcmpSocket for macOS (completed 2025-07-30)
3. ⏳ AsyncUdpSocket for Linux IP_RECVERR
4. ✅ Factory to select appropriate implementation

### Phase 3: Async Engine (Week 3)
1. Convert TracerouteEngine to async
2. Implement concurrent probe sending
3. Add immediate response collection
4. Handle timeouts and cancellation

### Phase 4: Enrichment Service (Week 4)
1. Implement parallel DNS resolver
2. Add concurrent ASN lookups
3. Background enrichment processing
4. Result aggregation

### Phase 5: Testing & Optimization (Week 5)
1. Performance benchmarks
2. Latency measurements
3. Platform-specific testing
4. Documentation updates

## Expected Improvements

### Performance
- **Response latency**: 200ms+ → <1ms
- **Total runtime**: 30-50% faster for full traces
- **CPU usage**: Lower due to event-driven model
- **Memory usage**: Similar or slightly higher due to async runtime

### User Experience
- **Still works without admin**: No regression in permissions
- **Faster results**: Especially noticeable on fast networks
- **Better timeout handling**: More accurate timing
- **Streaming results**: Can show results as they arrive

### Code Quality
- **Unified implementation**: One codebase for all platforms
- **Better testability**: Async code is easier to test
- **Future-proof**: Ready for IPv6, TCP, HTTP/3
- **Maintainability**: Less platform-specific code

## Migration Strategy

1. **Parallel Development**: Build async version alongside sync
2. **Feature Flag**: `--async` flag to test new implementation
3. **Gradual Rollout**: 
   - v0.4.0-beta: Async behind flag
   - v0.4.0: Async by default, sync behind flag
   - v0.5.0: Remove sync code
4. **Backwards Compatibility**: Same CLI interface and output

## Dependencies

```toml
[dependencies]
tokio = { version = "1.35", features = ["full", "windows-sys", "net", "time", "sync"] }
tokio-util = "0.7"
futures = "0.3"
async-trait = "0.1"

[target.'cfg(windows)'.dependencies]
windows-sys = { version = "0.52", features = [
    "Win32_Foundation",
    "Win32_NetworkManagement_IpHelper", 
    "Win32_System_Threading",
    "Win32_System_IO",
] }
```

## Success Metrics

1. **Response Processing Time**: < 1ms from packet arrival
2. **No Permission Regression**: Works without admin on all platforms
3. **Performance Improvement**: 30%+ faster full traces
4. **Code Reduction**: 20% less platform-specific code
5. **Test Coverage**: 90%+ for async components

## Risks and Mitigations

### Risk: Tokio adds complexity
**Mitigation**: Good documentation, careful API design, gradual migration

### Risk: Platform differences in async behavior  
**Mitigation**: Extensive testing on all platforms, abstraction layer

### Risk: Increased binary size
**Mitigation**: Feature flags to exclude unused tokio features

### Risk: Debugging async code
**Mitigation**: Good logging, tokio-console integration, trace spans

## Next Steps

1. Review and approve this plan
2. Create feature branch `feature/async-traceroute`
3. Set up tokio dependencies
4. Start with Phase 1 implementation
5. Weekly progress reviews

## Platform Implementation Details

### macOS Implementation (Completed 2025-07-30)

The macOS async implementation uses DGRAM ICMP sockets with Tokio for immediate response notification:

#### Key Features:
- **Socket Type**: DGRAM ICMP (works without root on macOS)
- **Async Model**: Tokio UdpSocket with background receiver task
- **Response Handling**: Oneshot channels for per-probe response delivery
- **Performance**: 16-115x faster than synchronous implementation

#### Architecture:
1. **Background Receiver**: Dedicated task continuously receives ICMP responses
2. **Oneshot Channels**: Each probe gets a dedicated channel for its response
3. **Immediate Notification**: Responses wake up waiting futures immediately
4. **Zero Polling**: No polling loops or sleep delays

#### Performance Results:
- **Sync mode**: ~1.15 seconds average
- **Async mode**: ~0.01-0.07 seconds average
- **Improvement**: Response processing latency reduced from 200ms+ to <1ms

### Windows Implementation (Completed earlier)

Uses IcmpSendEcho2 with Windows events wrapped in Tokio async primitives.

### Linux Implementation (Pending)

Will use either DGRAM ICMP or UDP with IP_RECVERR for non-root operation.

## Conclusion

This async migration will solve our immediate notification problem while setting ftr up for future enhancements. By using Tokio, we get immediate response processing, maintain non-admin usage, and create a cleaner, more maintainable codebase.