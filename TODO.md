# TODO List for ftr

## Dependency Reduction

- [ ] Custom DNS client to replace `hickory-resolver` (TXT queries for Team Cymru ASN, PTR queries for rDNS — ~200 lines of UDP DNS over tokio, eliminates ~100 transitive crates)
- [ ] Evaluate replacing `clap` with manual arg parsing (clap brings ~10 crates)
- [ ] Evaluate replacing `serde`/`serde_json` with `miniserde` or manual JSON (serde brings ~5 crates)

## Features

- [ ] Platform and timestamp in JSON output
- [ ] Streaming traceroute API (real-time hop updates, enables TUI/live dashboards)
- [ ] TCP traceroute mode (TCP SYN packets, bypasses ICMP-blocking firewalls)
- [ ] Bufferbloat testing (baseline vs saturated latency, RPM metrics)
- [ ] Multipath/ECMP discovery (Dublin Traceroute-style flow enumeration)
- [ ] IPv6 support (ICMPv6, UDP6, TCP6)
- [ ] IXP/peering point detection (PeeringDB API, reverse DNS patterns) — see `docs/IXP_DETECTION_PROPOSAL.md`
- [ ] WHOIS fallback for network ownership — see `docs/WHOIS_ENHANCEMENT_PROPOSAL.md`
- [ ] Disk cache for DNS/ASN lookups
- [ ] Auto-updating TUI mode (re-run traceroute on interval, show jitter/loss stats)

## Platform-Specific

- [ ] Windows: UDP mode, MSI installer, more integration tests
- [ ] FreeBSD: test on 13.x, consider ports submission
