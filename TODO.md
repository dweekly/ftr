# TODO List for ftr

## Architectural

- [ ] Remove "async" naming throughout codebase (`async_api.rs` -> `api.rs`, `AsyncProbeSocket` -> `ProbeSocket`, etc.)
- [ ] Replace `async-trait` with native `async fn in trait` (MSRV 1.82 supports this)
- [ ] Replace `futures` crate with `tokio::task::JoinSet`
- [ ] Replace `reqwest` with a lighter HTTP client (`ureq` or `minreq`)
- [ ] Replace `pnet` with manual ICMP header parsing
- [ ] Replace `anyhow` with `TracerouteError` everywhere in the library
- [ ] Consolidate `ipnet` and `ip_network` — use only `ip_network`

## Features

- [ ] Streaming traceroute API (real-time hop updates, enables TUI/live dashboards)
- [ ] Bufferbloat testing (baseline vs saturated latency, RPM metrics)
- [ ] Multipath/ECMP discovery (Dublin Traceroute-style flow enumeration)
- [ ] TCP traceroute mode (TCP SYN packets, bypasses ICMP-blocking firewalls)
- [ ] IPv6 support (ICMPv6, UDP6, TCP6)
- [ ] IXP/peering point detection (PeeringDB API, reverse DNS patterns) — see `docs/IXP_DETECTION_PROPOSAL.md`
- [ ] WHOIS fallback for network ownership — see `docs/WHOIS_ENHANCEMENT_PROPOSAL.md`
- [ ] Platform and timestamp in JSON output
- [ ] Disk cache for DNS/ASN lookups
- [ ] Replace `libc` with `nix` crate
- [ ] Auto-updating TUI mode (re-run traceroute on interval, show jitter/loss stats)

## Platform-Specific

- [ ] Windows: UDP mode, MSI installer, more integration tests
- [ ] FreeBSD: test on 13.x, consider ports submission
