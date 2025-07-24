# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/dweekly/ftr/compare/v0.2.1...HEAD
[0.2.1]: https://github.com/dweekly/ftr/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/dweekly/ftr/compare/v0.1.2...v0.2.0
[0.1.2]: https://github.com/dweekly/ftr/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/dweekly/ftr/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/dweekly/ftr/releases/tag/v0.1.0
