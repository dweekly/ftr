# API Ergonomics Refactor Plan - Option B: Services Container

## Overview
Transform the current cache-centric, functional API into a service-oriented, method-based API that reflects what users want to do rather than how it's implemented.

## Core Design Principles
1. **Services, not caches**: Name things for what they do, not how they do it
2. **Methods, not functions**: Use `service.lookup(ip)` instead of `lookup_with_cache(ip, &cache, resolver)`
3. **Hide implementation details**: Caching is internal optimization, not part of the public API
4. **Progressive disclosure**: Simple things simple, complex things possible

## Proposed Structure

### Ftr with Services Container

```rust
pub struct Ftr {
    services: Services,
}

pub struct Services {
    pub asn: Arc<RwLock<AsnLookup>>,
    pub rdns: Arc<RwLock<RdnsLookup>>,
    pub stun: Arc<RwLock<StunClient>>,
}
```

### Service Implementations

#### AsnLookup Service
```rust
/// ASN (Autonomous System Number) lookup service
pub struct AsnLookup {
    // Private implementation details
    cache: Arc<RwLock<IpNetworkTable<AsnInfo>>>,
    resolver: Option<Arc<TokioResolver>>,
}

impl AsnLookup {
    /// Create a new ASN lookup service
    pub fn new() -> Self {
        Self::with_resolver(None)
    }
    
    /// Create with a specific DNS resolver
    pub fn with_resolver(resolver: Option<Arc<TokioResolver>>) -> Self {
        Self {
            cache: Arc::new(RwLock::new(IpNetworkTable::new())),
            resolver,
        }
    }
    
    /// Look up ASN information for an IPv4 address
    pub async fn lookup(&self, ip: Ipv4Addr) -> Result<AsnInfo, AsnError> {
        // Check cache first (internal detail)
        if let Some(info) = self.get_from_cache(&ip) {
            return Ok(info);
        }
        
        // Perform network lookup
        let info = self.fetch_from_network(ip).await?;
        
        // Cache the result (internal detail)
        self.store_in_cache(ip, info.clone());
        
        Ok(info)
    }
    
    // Advanced cache control for power users
    pub fn clear_cache(&self) {
        let mut cache = self.cache.write().unwrap();
        cache.clear();
    }
    
    pub fn cache_stats(&self) -> CacheStats {
        let cache = self.cache.read().unwrap();
        CacheStats {
            entries: cache.len(),
            // ... other stats
        }
    }
}
```

#### RdnsLookup Service
```rust
/// Reverse DNS lookup service
pub struct RdnsLookup {
    // Private implementation details
    cache: Arc<RwLock<HashMap<IpAddr, CacheEntry>>>,
    resolver: Option<Arc<TokioResolver>>,
    ttl: Duration,
}

impl RdnsLookup {
    /// Create a new reverse DNS lookup service
    pub fn new() -> Self {
        Self::with_ttl(Duration::from_secs(3600))
    }
    
    /// Create with custom TTL for cache entries
    pub fn with_ttl(ttl: Duration) -> Self {
        Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
            resolver: None,
            ttl,
        }
    }
    
    /// Create with a specific DNS resolver
    pub fn with_resolver(mut self, resolver: Arc<TokioResolver>) -> Self {
        self.resolver = Some(resolver);
        self
    }
    
    /// Look up the hostname for an IP address
    pub async fn lookup(&self, ip: IpAddr) -> Result<String, ReverseDnsError> {
        // Check cache first (internal)
        if let Some(hostname) = self.get_from_cache(&ip) {
            return Ok(hostname);
        }
        
        // Perform DNS lookup
        let hostname = self.fetch_from_dns(ip).await?;
        
        // Cache the result (internal)
        self.store_in_cache(ip, hostname.clone());
        
        Ok(hostname)
    }
    
    // Cache control
    pub fn clear_cache(&self) {
        let mut cache = self.cache.write().unwrap();
        cache.clear();
    }
}
```

#### StunClient Service
```rust
/// STUN client for public IP detection
pub struct StunClient {
    // Private implementation details
    server_cache: Arc<RwLock<HashMap<String, ServerAddresses>>>,
    servers: Vec<String>,
    timeout: Duration,
}

impl StunClient {
    /// Create a new STUN client with default servers
    pub fn new() -> Self {
        Self::with_servers(vec![
            "stun.l.google.com:19302".to_string(),
            "stun1.l.google.com:19302".to_string(),
        ])
    }
    
    /// Create with custom STUN servers
    pub fn with_servers(servers: Vec<String>) -> Self {
        Self {
            server_cache: Arc::new(RwLock::new(HashMap::new())),
            servers,
            timeout: Duration::from_millis(500),
        }
    }
    
    /// Get the public IP address
    pub async fn get_public_ip(&self) -> Result<IpAddr, StunError> {
        // Try servers in order (caching resolved addresses internally)
        for server in &self.servers {
            if let Ok(ip) = self.query_server(server).await {
                return Ok(ip);
            }
        }
        Err(StunError::AllServersFailed)
    }
    
    /// Detect NAT type (future enhancement)
    pub async fn detect_nat_type(&self) -> Result<NatType, StunError> {
        // Implementation
    }
}
```

### Ftr Methods

```rust
impl Ftr {
    /// Create a new Ftr instance with default services
    pub fn new() -> Self {
        Self {
            services: Services::default(),
        }
    }
    
    /// Create with custom services
    pub fn with_services(
        asn: Option<AsnLookup>,
        rdns: Option<RdnsLookup>,
        stun: Option<StunClient>,
    ) -> Self {
        Self {
            services: Services::new(asn, rdns, stun),
        }
    }
    
    // Convenience methods that hide the Arc<RwLock> complexity
    
    /// Look up ASN information
    pub async fn lookup_asn(&self, ip: Ipv4Addr) -> Result<AsnInfo, AsnError> {
        self.services.asn.read().await.lookup(ip).await
    }
    
    /// Look up reverse DNS
    pub async fn lookup_rdns(&self, ip: IpAddr) -> Result<String, ReverseDnsError> {
        self.services.rdns.read().await.lookup(ip).await
    }
    
    /// Get public IP address
    pub async fn get_public_ip(&self) -> Result<IpAddr, StunError> {
        self.services.stun.read().await.get_public_ip().await
    }
    
    /// Clear all caches
    pub async fn clear_all_caches(&self) {
        let asn = self.services.asn.read().await;
        let rdns = self.services.rdns.read().await;
        asn.clear_cache();
        rdns.clear_cache();
    }
    
    /// Get cache statistics
    pub async fn cache_stats(&self) -> AllCacheStats {
        let asn = self.services.asn.read().await;
        let rdns = self.services.rdns.read().await;
        
        AllCacheStats {
            asn: asn.cache_stats(),
            rdns: rdns.cache_stats(),
        }
    }
}
```

## Usage Examples

### Basic Usage
```rust
let ftr = Ftr::new();

// Simple, clean API
let asn_info = ftr.lookup_asn(ipv4_addr).await?;
let hostname = ftr.lookup_rdns(ip_addr).await?;
let public_ip = ftr.get_public_ip().await?;
```

### Advanced Usage
```rust
// Custom configuration
let asn = AsnLookup::with_resolver(Some(custom_resolver));
let rdns = RdnsLookup::new()
    .with_ttl(Duration::from_secs(300))
    .with_resolver(custom_resolver);
let stun = StunClient::with_servers(vec!["my.stun.server:3478".to_string()]);

let ftr = Ftr::with_services(Some(asn), Some(rdns), Some(stun));

// Direct service access for fine control
let asn_service = ftr.services.asn.read().await;
let info = asn_service.lookup(ip).await?;
asn_service.clear_cache();
```

### Traceroute Integration
```rust
impl Ftr {
    pub async fn trace_with_config(&self, config: TracerouteConfig) -> Result<TracerouteResult> {
        // Pass services to the engine
        let engine = create_engine(config, &self.services);
        engine.run().await
    }
}
```

## Migration Path

### Phase 1: Add New Service Types
1. Create `AsnLookup`, `RdnsLookup`, `StunClient` structs
2. Add `lookup()` methods to each
3. Keep old `*Cache` types as aliases temporarily

### Phase 2: Update Services Container
1. Rename `Caches` to `Services`
2. Update field names from `*_cache` to service names
3. Update field types to new service types

### Phase 3: Add Ftr Convenience Methods
1. Add `lookup_asn()`, `lookup_rdns()`, `get_public_ip()` to Ftr
2. These hide the Arc<RwLock> complexity

### Phase 4: Update Internal Usage
1. Replace `lookup_asn_with_cache()` calls with `asn.lookup()`
2. Replace `reverse_dns_lookup_with_cache()` with `rdns.lookup()`
3. Update all internal code

### Phase 5: Deprecate Old API
1. Mark old functions as `#[deprecated]`
2. Update documentation
3. Release as v0.6.0

### Phase 6: Remove Old API
1. Remove deprecated functions in v0.7.0
2. Remove old type aliases

## Benefits

1. **Intuitive API**: `ftr.lookup_asn(ip)` clearly expresses intent
2. **Service-oriented**: Focus on what, not how
3. **Progressive disclosure**: Simple default API with advanced options
4. **Consistent patterns**: All services follow same method patterns
5. **Encapsulation**: Implementation details hidden
6. **Extensible**: Easy to add new services or methods

## Comparison

### Before (v0.5.0)
```rust
use ftr::asn::lookup::lookup_asn_with_cache;
use ftr::dns::reverse::reverse_dns_lookup_with_cache;

let asn_cache = Arc::new(RwLock::new(AsnCache::new()));
let rdns_cache = Arc::new(RwLock::new(RdnsCache::with_default_ttl()));

let asn_info = lookup_asn_with_cache(ip, &asn_cache, None).await?;
let hostname = reverse_dns_lookup_with_cache(ip, &rdns_cache, None).await?;
```

### After (v0.6.0)
```rust
let ftr = Ftr::new();

let asn_info = ftr.lookup_asn(ip).await?;
let hostname = ftr.lookup_rdns(ip).await?;
```

## Open Questions

1. Should we provide sync versions of lookup methods for simple cases?
2. Should services be clonable for sharing between Ftr instances?
3. Should we add a generic `Service` trait that all services implement?
4. How much cache control should we expose (clear, resize, stats)?

## Conclusion

This design transforms ftr from a cache-centric library to a service-oriented one, where caching is an invisible optimization rather than a prominent API feature. The result is cleaner, more intuitive, and more Rust-idiomatic.