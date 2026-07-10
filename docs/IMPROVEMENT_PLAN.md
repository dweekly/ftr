# ftr Improvement Plan

Sequenced plan from a full-project review (code, docs, CI, and a feature-gap
analysis against SwiftFTR 0.13.0) against Rust best practices as of mid-2026.
One entry per shippable stage; delete stages as they merge (git has the history).

Context: ftr is in maintenance mode (SwiftFTR is the primary macOS client), but
has external users (GitHub stars, crates.io, APT repo, one open issue — #22
requesting IPv6). Priorities therefore lean correctness, docs accuracy, and
supply-chain hygiene first; feature work (IPv6, streaming) second; SwiftFTR
parity ports (multipath, probes) only as appetite allows.

## Stage 1 — Docs accuracy & hygiene (1 PR, no code changes)

- README Options table: document all 16 flags from `src/main.rs` (missing:
  `--protocol`, `--socket-mode`, `-q/--queries`, `-v`, `-p/--port`,
  `--public-ip`, `--stun-server`, `--json`); fix `-i` documented default
  (README says 5, code default is 0).
- Fix MSRV references: `README.md:334` and `CLAUDE.md` say 1.82; actual is
  1.85 (`Cargo.toml`).
- Remove false claim that `cargo install ftr` is unavailable (`README.md:260`)
  — it is published.
- CLAUDE.md refresh: version 0.7.0 (says 0.6.0); `dns/` module is a custom
  resolver, not hickory-resolver.
- Add an Examples section to README covering `examples/` (8 files, currently
  orphaned); rename `examples/test_v0_6_library.rs` (version-pinned name).
- Delete `.github/workflows/debug-test.yml` (dead debug scaffolding).
- TODO.md: remove shipped "custom DNS client" item.
- Fix doc/constant drift: `TimingConfig` doc says poll interval default 100ms,
  constant is 1ms.

## Stage 2 — Correctness bug fixes (1–2 PRs, patch release v0.7.1)

- **Enrichment ignores injected Services** (HIGH): `EnrichmentService::new()`
  builds a fresh `Services` (`src/enrichment/service.rs:36`), so
  `Ftr::with_caches` prewarmed ASN/rDNS caches never reach hop enrichment and
  each trace runs two disjoint cache sets. Add
  `EnrichmentService::new_with_services` and thread the engine's `Services`
  through (`src/traceroute/engine.rs`).
- **StunClient custom servers ignored** (MEDIUM): `with_servers` stores
  servers but the query path uses the hardcoded `STUN_SERVERS` constant
  (`src/public_ip/stun.rs:160-170`). Make the query path use `self.servers`.
- **Remove `env::set_var` intra-process signaling** (HIGH): `FTR_VERBOSE` set
  in `src/traceroute/api.rs:92` and read in the socket factory; `FTR_STUN_SERVER`
  set in `main.rs:184`. Races across concurrent traces and becomes `unsafe`
  under edition 2024 — thread these through config structs instead. This is
  the edition-2024 blocker.
- **Engine error re-wrapping** loses variants: `api.rs:113-123` collapses any
  engine error into `SocketError(String)`. Preserve the original variant.
- **DNS resolver hardening** (`src/dns/resolver.rs`): validate response query
  ID / QR bit / question section (currently accepts any datagram on the
  unconnected socket); add one retransmit before the 5s timeout; add a
  fallback server; check the TC bit instead of silently parsing truncated
  responses. Larger follow-on (separate PR): read system resolvers from
  `/etc/resolv.conf` / platform equivalents instead of hardcoded 1.1.1.1 —
  currently broken on split-horizon/VPN/filtered networks.

## Stage 3 — CI & supply chain to 2026 baseline (1–2 PRs)

- SHA-pin all GitHub Actions (currently mutable tags incl. floating
  `dtolnay/rust-toolchain@master`) + Dependabot for action updates.
- Add cargo-deny with a reviewed `deny.toml` (licenses/bans/advisories/sources);
  keep or drop standalone cargo-audit.
- Add `cargo-semver-checks-action` — baseline for a published library crate.
- Coverage: switch tarpaulin → cargo-llvm-cov (cross-platform, less invasive —
  likely fixes the flakiness that forced `continue-on-error: true`); remove the
  contradictory `fail_ci_if_error: true`.
- Releases: adopt crates.io Trusted Publishing (OIDC) instead of a long-lived
  token; add SHA256SUMS + GitHub artifact attestations (SLSA) for release
  binaries; fix the two-phase draft-release trigger so tagging can't leave
  crates.io/APT silently unpublished; consider macOS release artifacts
  (currently none — brew tap builds from source).

## Stage 4 — API cleanup & modernization (1 PR, minor release v0.8.0)

Bundle the breaking changes:

- Edition 2021 → 2024 (unblocked by Stage 2's `set_var` removal); MSRV stays 1.85.
- `#[non_exhaustive]` on public enums that will grow (`TracerouteError`,
  `SegmentType`, `ProbeProtocol`, `SocketMode`, `IpVersion`, error enums) —
  prerequisite for adding IPv6/TCP variants non-breakingly later.
- Remove dead/duplicate public surface: unused `Caches` (`src/caches.rs`),
  duplicate `TimingConfig` (`src/config/timing.rs` vs `src/traceroute/config.rs`),
  duplicate `ProbeInfo`/`ProbeResponse` (`src/socket/mod.rs:151-181` vs
  `src/probe.rs`); make `Ftr.services` non-pub; narrow `pub mod socket`/`probe`.
- `TracerouteConfigBuilder::build()` → typed `ConfigError` instead of `String`.
- Dependency minor bumps: tokio 1.47→1.52, criterion 0.7→0.8.

## Stage 5 — Performance & reliability (2 PRs)

- Replace 1ms busy-poll receive loops (`linux.rs`, `macos.rs`, `bsd.rs`) with
  tokio `AsyncFd` readiness — the dominant avoidable CPU cost; also fixes
  detached receiver tasks outliving the trace (tie receivers to the engine's
  `JoinSet`), removes `env::var("CI")` reads inside poll loops, and the
  per-packet throwaway struct allocations.
- Consider shared-socket receive demux instead of socket-per-probe. SwiftFTR
  lesson (0.8.0 regression): each concurrent socket needs a **unique ICMP
  identifier**, validated on Echo Reply AND on the id embedded in Time
  Exceeded/Unreachable payloads — kernels demux datagram-ICMP replies by id.
- Drop redundant double-locking: outer `tokio::RwLock` around internally
  locked `AsnCache`/`RdnsCache`; make `RdnsCache::get` not take a write lock
  per read.
- Testing hardening: proptest + cargo-fuzz targets for `src/socket/icmp.rs`
  (reject IHL < 5 while at it) and the DNS parser; unit tests for the `unsafe`
  `recvmsg`/CMSG path (linux) and Windows reply-struct reinterpret; gate live-
  network tests behind an env var and serialize them (SwiftFTR's
  `NetworkTestGate` pattern) instead of letting them flake CI.

## Stage 6 — IPv6 support (release train, closes issue #22)

The only open user request. Currently v4-only: factory returns
`Ipv6NotSupported`, ASN returns `NotFound` for v6, STUN v6 is a stub. Bundle
v6 trace + v6 ASN enrichment in one release (SwiftFTR shipped these together —
each is a half-feature alone); STUN v6 can trail.

- ICMPv6 sockets via socket2 (`Domain::IPV6`/`Protocol::ICMPV6`,
  `IPV6_UNICAST_HOPS`, `IPV6_RECVHOPLIMIT`). Note socket2 has no `ICMP6_FILTER`
  helper (rust-lang/socket2#199) — set it via raw `setsockopt` through libc or
  filter in userspace. Kernel does NOT include the IPv6 header on raw v6
  receive (unlike v4) — parsing differs.
- v6 ASN: Team Cymru `origin6.asn.cymru.com` nibble-reversed queries.
- STUN v6: XOR-MAPPED-ADDRESS family 0x02, un-XOR bytes 4..15 against the
  transaction ID (RFC 5389 §15.2).
- rDNS `ip6.arpa` construction already exists (`dns/resolver.rs:76-85`).
- `--preferred-family`/auto selection; consider `getaddrinfo` AI_V4MAPPED for
  NAT64 transparency (SwiftFTR does this).
- Contract lessons from SwiftFTR: emit canonical (`inet_ntop`-stable) address
  strings; never strip `%zone` from link-local addresses; single family-
  agnostic entry point, family in error *context* not error *type*.

## Stage 7 — Feature ports from SwiftFTR (optional, by appetite)

Ranked by fit for a traceroute tool with external users:

1. **Streaming trace API** — `impl Stream<Item = StreamingHop>` emitting hops
   in arrival order with a re-probe phase for rate-limited routers. Best
   library-consumer win; SwiftFTR's `StreamingTrace` is the reference.
2. **UDP 5-tuple multipath/ECMP discovery** — ftr on Linux already has
   unprivileged UDP traceroute, so true Dublin/Paris-style flow variation is
   *more* attainable here than it was for SwiftFTR (which shipped ICMP-ID
   variation and documented it under-discovers, deferring UDP to its roadmap).
   A differentiating feature, not just parity.
3. **TCP/UDP connectivity probes** — connected-UDP trick (ICMP unreachable
   surfaces as `ECONNREFUSED`, no privileges) and non-blocking TCP connect.
   Small, self-contained.
4. **Bufferbloat/RPM testing** — probably out of scope for ftr; it drags in
   HTTP load generation and third-party endpoints. Skip unless a user asks.
