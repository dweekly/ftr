# FreeBSD Plan Critique

Below are specific concerns and proposed changes for FREEBSD_PLAN.md:

## Research Summary
- IPv6: mention unprivileged DGRAM ICMPv6 support via `IPPROTO_ICMPV6`.
- Rate limiting: handle `net.inet.icmp.icmplim` errors gracefully and warn users if defaults are restrictive.

## Compatibility Matrix
- UDP error capture: clarify that a raw ICMP socket must run in parallel to catch TTL‐exceeded responses.
- TCP Stream mode: verify that setting `IP_TTL` on TCP sockets works correctly on FreeBSD.

## Implementation Details
- Raw sockets: confirm `IP_HDRINCL` or header stripping behavior matches expectations.
- Dependencies: ensure `socket2` and `pnet` build cleanly on FreeBSD.

## Testing & CI
- CI setup: specify exact GitHub Action (`vmactions/freebsd-vm`) or Cirrus CI config for FreeBSD.
- Automated tests: add an `#[cfg(target_os="freebsd")]` smoke test in the existing test suite.

## Documentation
- MULTI_MODE.md: update to include FreeBSD’s DGRAM ICMP path.
- Installation: add pkgsrc or binary tarball instructions for FreeBSD.
- Version bump: remember to update version in Cargo.toml and CHANGELOG.md.

## Potential Pitfalls
- Firewall: warn that PF/BPF may block raw sockets on FreeBSD by default.
- Sysctl automation: include a diagnostic check for restrictive `icmplim` settings.
