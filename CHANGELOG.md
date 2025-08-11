# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.2] - TBD

### Changed
- **BREAKING**: Removed synchronous implementation - library is now async-only
  - Eliminated `--sync-mode` CLI flag (async is the only mode)
  - Removed sync socket implementations and TracerouteEngine
  - Simplified public API to only expose async functions
  - All library users must now use async/await (with tokio runtime)

### Removed
- Sync socket implementations (`icmp_v4.rs`, `udp.rs`, `factory.rs`)
- Sync TracerouteEngine and API wrapper
- `--sync-mode` command-line flag
- `create_probe_socket` family of functions from public API
- `test_socket.rs` example that used sync API

### Internal
- Consolidated error types into single `TracerouteError` enum
- Added `socket::utils` module for permission check helpers
- Reduced codebase by ~4,800 lines of code
- Simplified maintenance with single implementation path

### Performance
- Async-only implementation maintains 16-115x faster response processing
- Eliminated 200ms+ polling delays from sync implementation

## [0.3.1] - 2025-08-01

### Added
- **Async Implementation** - New default async/await traceroute engine with **10x performance improvement** for short probe timeouts
  - Immediate response processing without polling delays  
  - Full async support for all platforms (Windows, macOS, Linux, FreeBSD/OpenBSD)
  - `--sync-mode` flag available for legacy synchronous implementation
- **Platform-Specific Optimizations**
  - Windows: Optimized ICMP API handling saves 600ms+ per traceroute
  - macOS: Per-probe socket implementation for reliable TimeExceeded reception
  - BSD: New async implementation using raw ICMP sockets
- **Performance Enhancements**
  - Background pre-fetching for DNS and ASN lookups during traceroute
  - STUN cache pre-warming for faster public IP detection
  - CI build caching reduces GitHub Actions time

### Changed
- Async is now the default mode on all platforms
- Improved test reliability with serial execution for cache tests
- Updated CI to use macos-15

### Fixed
- macOS async now properly shows all intermediate hops (was only showing destination)
- Windows timeout handling for reliable operation with short timeouts
- Duplicate country code display in ASN info
- `--no-enrich` flag now properly suppresses all enrichment data
- Various test flakiness issues in CI

## [0.3.0] - 2025-07-28

### Added
- **Major Library Refactoring** - Complete transformation from monolithic CLI to modular library
  - High-level async API with `trace()` and `trace_with_config()` functions
  - Comprehensive configuration via `TracerouteConfigBuilder` with fluent API
  - Structured error handling with `TracerouteError` enum for programmatic error handling
  - Modular architecture with separate modules for ASN, DNS, public IP, and socket operations
  - Extensive documentation for all public APIs with examples
  - New examples demonstrating library usage patterns
- **Caching Infrastructure**
  - ASN lookup caching with configurable TTL (default 24 hours)
  - Reverse DNS caching with configurable TTL (default 1 hour)
  - Thread-safe global caches using Arc<Mutex<>>
  - Significant performance improvements for repeated lookups
- **Enhanced Testing**
  - Comprehensive unit tests for all modules
  - Integration tests for library API
  - Test coverage for main.rs CLI functionality
  - Structured error handling tests
  - Platform-specific test improvements
- **Error Handling Improvements**
  - `InsufficientPermissions` error with structured fields for required permissions and suggestions
  - `NotImplemented` error for features like TCP traceroute
  - `Ipv6NotSupported` error for IPv6 targets
  - Clear, actionable error messages for all error types
- **Configuration Enhancements**
  - Public IP parameter in TracerouteConfig to avoid repeated detection
  - Convenience methods like `queries()` and `parallel_probes()`
  - Better validation with descriptive error messages
- **Documentation Updates**
  - Comprehensive library documentation in lib.rs
  - Error handling guide with examples
  - Module-level documentation for all public modules
  - Platform-specific implementation notes
- OpenBSD support (OpenBSD 7.x)
  - Raw ICMP socket implementation with IP_HDRINCL support
  - Requires root privileges (identical behavior to FreeBSD)
  - Tested on OpenBSD 7.7 ARM64

### Changed
- **API Changes**
  - `AsnInfo.asn` changed from String to u32 (breaking change)
  - Added `display_asn()` method for formatting ASN with "AS" prefix
  - Improved error types to be more specific and actionable
- **Performance Optimizations**
  - Parallel ASN and DNS lookups during hop enrichment
  - Caching reduces redundant network requests
  - More efficient data structures
- **CI/CD Improvements**
  - FreeBSD CI reduced to single version (14.0) for efficiency
  - Better test organization and coverage reporting
- **Code Organization**
  - Core types moved from main.rs to library modules
  - Traceroute engine extracted to dedicated module
  - Better separation of concerns throughout codebase

### Fixed
- ASN lookup for private/special IPs now returns 0 instead of failing
- Memory efficiency improvements in caching implementation
- Race conditions in concurrent lookups
- Documentation accuracy for TCP support (marked as not implemented)
- Platform-specific socket mode documentation

## [0.2.4] - 2025-07-27

### Added
- FreeBSD support (FreeBSD 13.x and 14.x)
  - Raw ICMP socket implementation with IP_HDRINCL support
  - Automatic root privilege detection and clear error messages
  - FreeBSD-specific build instructions and dependencies
  - CI/CD integration with vmactions/freebsd-vm for automated testing
  - Comprehensive FreeBSD-specific tests
- Generic root privilege checking for platforms without non-root traceroute capability
- Warning messages for public IP detection failures with platform-specific hints
- Platform-specific native-tls configuration (vendored only on Linux)

### Changed
- Socket factory now properly identifies FreeBSD capabilities (no DGRAM ICMP support)
- Improved error messages for platforms requiring root privileges
- Updated documentation to clarify FreeBSD requirements

### Fixed
- Raw ICMP sockets now work correctly on FreeBSD with IP_HDRINCL
- Build issues on FreeBSD with native-tls-vendored feature

## [0.2.3] - 2025-07-26

### Added
- Windows support (Windows 10/11, including ARM64)
  - Windows ICMP socket implementation using Windows ICMP API (IcmpCreateFile/IcmpSendEcho)
  - Automatic Winsock initialization with thread-safe OnceLock pattern
  - Windows-specific error handling and status code mapping
  - Build script for Npcap SDK integration
  - Support for both x64 and ARM64 Windows architectures
- Windows-specific tests for socket functionality

## [0.2.2] - 2025-07-24

### Added
- Display detected public IP address in output
- Minimalist printing for silent hops (just TTL number instead of "* * *")
- Structured JSON output with `--json` flag for programmatic use
- Verbose mode with `-v/--verbose` flag to show socket mode details
- Target port selection with `-p/--port` option for UDP mode (default 443)
- Warning when port is specified for non-UDP protocols
- Integration tests for CLI functionality
- Input validation for start-ttl (must be >= 1) and probe-timeout-ms (must be > 0)
- Version display with `--version` shows release version or dev version with "-UNRELEASED" suffix
- Version field included in JSON output for programmatic version checking

### Changed
- Improved user experience with cleaner output format
- Silent hops now use minimal space to reduce visual clutter
- Socket mode selection messages now only shown in verbose mode
- Socket mode selection now uses OS/protocol/privilege compatibility matrix
- Better error messages specific to each operating system
- Automatic selection of best available socket mode based on OS and privileges
- Exit with error code 1 when hostname resolution fails

## [0.2.1] - 2025-07-23

### Added
- Socket abstraction layer for multi-protocol support
  - Raw ICMP mode implementation (requires root/CAP_NET_RAW)
  - DGRAM ICMP mode implementation (Linux, configurable ping group)
  - UDP mode implementation with automatic fallback
- Factory pattern for automatic mode selection based on available permissions
- Library interface (`lib.rs`) for programmatic use
- Example program demonstrating socket abstraction
- Multiple probes per TTL support with `-q/--queries` option
  - Send multiple probes to discover all paths in load-balanced networks
  - Matches behavior of system traceroute utilities
  - Default remains 1 probe per hop for backward compatibility
- Linux IP_RECVERR support for privilege-free UDP traceroute
- Comprehensive test scripts for comparing ftr with system traceroute
- Enhanced pre-push hooks with mandatory security checks (`cargo audit`)

### Fixed
- UDP traceroute on Linux now properly shows multiple hops
  - Uses connect() on UDP sockets matching system traceroute behavior
  - Correctly handles recvmsg() returning 0 with valid control messages
  - Ensures ICMP error responses are received for all probes
- Fixed regression where traceroute continued displaying hops past the destination
- Display both hostname and IP address in reverse DNS lookups
- Socket errors now properly detected using OS error codes instead of string matching

### Changed
- Socket implementation refactored into modular architecture with factory pattern
- UDP implementation now uses one socket per probe to avoid port collisions
- Improved error handling with better error messages and suggested solutions
- Removed noisy UDP port 443 notification from output

### Technical Improvements
- Modular socket implementations in `src/socket/` directory
- Trait-based socket abstraction for protocol independence
- Enhanced UDP implementation with ICMP response parsing
- Documentation for UDP traceroute on Linux added to `docs/UDP_TRACEROUTE_LINUX.md`
- Documentation for multi-mode probing added to `docs/MULTI_MODE.md`
- Updated AGENTS.md with VM guidelines and shared directory information
- Prepared groundwork for future protocol support (TCP, IPv6)

## [0.2.0] - 2025-07-21

### Added
- ISP detection via public IP address lookup
  - Automatically detects user's public IP using HTTP services (ipify, ipinfo, checkip.amazonaws.com)
  - Falls back to DNS TXT record queries when HTTP is blocked (using whoami.ds.akahelp.net)
  - Only uses DNS method when resolver has private IP address
  - Looks up ASN of public IP to identify user's ISP
  - Improves hop classification accuracy even when public IP doesn't appear in traceroute
- Carrier Grade NAT (CGNAT) support
  - Recognizes 100.64.0.0/10 range as internal/private addresses
  - Properly classifies CGNAT addresses as LAN segment
- Reverse DNS (rDNS) lookup support
  - Shows hostnames for each hop (e.g., 'router.local', 'xe-1-2-3.ar01.city.isp.net')
  - Performs lookups in parallel with ASN queries for optimal performance
  - Can be disabled with `--no-rdns` flag
  - Clean display format: 'hostname (IP)' when available

### Changed
- Significantly improved traceroute performance
  - Early exit when complete path to destination is found
  - Reduced execution time from 3+ seconds to ~0.17 seconds for local IPs
  - No longer waits for all probes when destination is reached
- Skip public IP lookup when target is a private/internal address
- Enhanced "Performing ASN lookups" message to indicate when rDNS is also running

### Fixed
- Traceroute no longer waits for full timeout when tracing to local network addresses
- Improved ISP detection accuracy in various network configurations

## [0.1.2] - 2025-07-06

### Added
- APT repository installation instructions for Debian/Ubuntu users
- Release checklist documentation to ensure consistent release process

### Changed
- Optimized APT repository workflow to avoid downloading entire package pool
- Fixed aptly repository URL to use HTTP instead of HTTPS

### Documentation
- Added comprehensive Ubuntu/Debian installation instructions via APT repository
- Created RELEASE_CHECKLIST.md for maintaining release quality

## [0.1.1] - 2025-07-06

### Added
- Automated Debian/Ubuntu packaging with .deb files for amd64 and arm64
- APT repository hosting on Cloudflare R2 for package distribution
- GitHub Actions workflow for automatic .deb package creation on releases
- GPG signing for APT repository packages

### Changed
- Removed docs.rs badge as ftr is a binary-only crate

### Fixed
- Removed outdated manual APT repository setup documentation

## [0.1.0] - 2025-07-06

### Added
- Initial release of ftr (Fast TraceRoute)
- Fast parallel ICMP traceroute implementation
- Automatic ASN (Autonomous System Number) lookup for each hop
- Intelligent hop classification (LAN, ISP, Beyond)
- Cross-platform support (Linux, macOS, Windows)
- Configurable timeouts and probe intervals
- Option to disable ASN enrichment with `--no-enrich`
- Comprehensive test suite
- GitHub Actions CI/CD pipeline

### Features
- Parallel probing significantly reduces scan time
- Smart caching of ASN lookups to minimize DNS queries
- Clean, informative output with RTT measurements
- Support for both hostnames and IP addresses

[Unreleased]: https://github.com/dweekly/ftr/compare/v0.3.1...HEAD
[0.3.1]: https://github.com/dweekly/ftr/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/dweekly/ftr/compare/v0.2.3...v0.3.0
[0.2.3]: https://github.com/dweekly/ftr/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/dweekly/ftr/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/dweekly/ftr/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/dweekly/ftr/compare/v0.1.2...v0.2.0
[0.1.2]: https://github.com/dweekly/ftr/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/dweekly/ftr/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/dweekly/ftr/releases/tag/v0.1.0
