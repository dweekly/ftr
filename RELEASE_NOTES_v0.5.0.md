# ftr v0.5.0 Release Notes

## 🎉 Major Release: Service-Oriented API

We're excited to announce **ftr v0.5.0**, a major release that completely redesigns the library API to be more intuitive, performant, and future-proof. This release introduces a **service-oriented architecture** that eliminates global state and provides a clean, instance-based API.

## ✨ Highlights

### New Service-Oriented API
The library now uses a handle pattern with the `Ftr` struct as your main entry point:

```rust
use ftr::Ftr;

// Create an instance
let ftr = Ftr::new();

// Simple, intuitive methods
let result = ftr.trace("google.com").await?;
let asn_info = ftr.lookup_asn(ip).await?;
let hostname = ftr.lookup_rdns(ip).await?;
let public_ip = ftr.get_public_ip().await?;
```

### Direct Service Access
Access services directly without complex locking:

```rust
// Services are directly accessible - no Arc<RwLock> needed!
let asn_info = ftr.services.asn.lookup(ip).await?;
let stats = ftr.services.asn.cache_stats().await;
```

### IPv6 Future-Proofing
All APIs now accept `IpAddr` instead of `Ipv4Addr`, preparing for future IPv6 support:

```rust
// Works with both IPv4 and IPv6 addresses
let ip: IpAddr = "2001:4860:4860::8888".parse()?;
let result = ftr.lookup_asn(ip).await; // Returns appropriate error for IPv6 (for now)
```

### True Parallel Execution
- Complete isolation between `Ftr` instances
- No global state or shared caches
- Tests run at 767% CPU utilization
- 200+ tests complete in 36.8 seconds

## 🚨 Breaking Changes

This is a major release with breaking API changes. Please see the [Migration Guide](#migration-guide) below.

### Removed
- Global `trace()` and `trace_with_config()` functions
- Global static caches
- Direct cache access functions
- Global timing configuration overrides

### Changed
- All traceroute functions are now instance methods on `Ftr`
- Service methods take `IpAddr` instead of `Ipv4Addr`
- Caches are now internal to services

## 📚 Migration Guide

### Basic Migration

```rust
// Old (v0.4.x)
let result = ftr::trace("google.com").await?;

// New (v0.5.0)
let ftr = Ftr::new();
let result = ftr.trace("google.com").await?;
```

### Service Usage

```rust
// Old (v0.4.x) - Direct cache access
let asn_info = lookup_asn_with_cache(ip, &cache, resolver).await?;

// New (v0.5.0) - Clean service methods
let ftr = Ftr::new();
let asn_info = ftr.lookup_asn(ip).await?;
```

### Multiple Instances

```rust
// Each instance has independent caches
let ftr1 = Ftr::new();
let ftr2 = Ftr::new();

// These run completely independently
let result1 = ftr1.trace("google.com").await?;
let result2 = ftr2.trace("cloudflare.com").await?;
```

### Custom Configuration

```rust
// With timing configuration
let config = TracerouteConfigBuilder::new()
    .target("example.com")
    .timing(TimingConfig::fast())
    .build()?;
let result = ftr.trace_with_config(config).await?;

// With pre-populated caches
let ftr = Ftr::with_caches(Some(asn_cache), None, None);
```

## 🔧 Technical Improvements

- **Simplified Locking**: Removed unnecessary `Arc<RwLock>` wrapper around services
- **Better Cache Locality**: Instance-based design improves cache performance
- **Cleaner Architecture**: Service-oriented design with clear boundaries
- **Future-Proof**: APIs designed for IPv6 support without future breaking changes

## 📦 Installation

### Cargo
```bash
cargo install ftr --version 0.5.0
```

### Debian/Ubuntu
```bash
curl -fsSL https://ftr-apt.dweek.ly/pubkey.asc | sudo tee /etc/apt/keyrings/ftr.asc
echo "deb [signed-by=/etc/apt/keyrings/ftr.asc] https://ftr-apt.dweek.ly/debian stable main" | sudo tee /etc/apt/sources.list.d/ftr.list
sudo apt update && sudo apt install ftr
```

### macOS
```bash
brew tap dweekly/ftr
brew install ftr
```

## 🙏 Acknowledgments

Thanks to all contributors and users who provided feedback on the API design. Special thanks to the Rust community for guidance on the handle pattern and service-oriented architecture.

## 📝 Full Changelog

See [CHANGELOG.md](https://github.com/dweekly/ftr/blob/v0.5.0/CHANGELOG.md) for the complete list of changes.

## 🐛 Bug Reports

Found a bug? Please report it at [GitHub Issues](https://github.com/dweekly/ftr/issues).

---

**Note**: This is a major release with breaking changes. Please review the migration guide carefully when upgrading from v0.4.x.