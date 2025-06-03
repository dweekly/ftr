# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1] - 2025-01-06

### Added
- Automated Debian/Ubuntu packaging with .deb files for amd64 and arm64
- APT repository hosting on Cloudflare R2 for package distribution
- GitHub Actions workflow for automatic .deb package creation on releases
- GPG signing for APT repository packages

### Changed
- Removed docs.rs badge as ftr is a binary-only crate

### Fixed
- Removed outdated manual APT repository setup documentation

## [0.1.0] - 2025-01-06

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

[Unreleased]: https://github.com/dweekly/ftr/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/dweekly/ftr/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/dweekly/ftr/releases/tag/v0.1.0