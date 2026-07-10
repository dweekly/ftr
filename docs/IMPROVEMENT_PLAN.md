# ftr Improvement Plan

Sequenced plan from a full-project review (code, docs, CI, and a feature-gap
analysis against SwiftFTR 0.13.0) against Rust best practices as of mid-2026.
One entry per shippable stage; delete stages as they merge (git has the history).

Context: ftr is in maintenance mode (SwiftFTR is the primary macOS client), but
has external users (GitHub stars, crates.io, APT repo, one open issue — #22
requesting IPv6). Docs accuracy, correctness fixes, dependency updates,
CI/supply-chain hardening, and IPv6 validation spikes landed in PRs #23–#27;
what remains is below.

## Follow-ups from landed stages (small, independent)

- DNS resolver: read system resolvers (`/etc/resolv.conf` / platform
  equivalents) instead of the hardcoded 1.1.1.1 → 8.8.8.8 chain — currently
  degraded on split-horizon/VPN/filtered networks. TCP fallback on truncated
  (TC) responses (`DnsError::Truncated` exists; nothing retries over TCP).
- Releases: adopt crates.io Trusted Publishing (OIDC) — requires one-time
  configuration on crates.io by the maintainer, then swap the token step in
  `release.yml` for `rust-lang/crates-io-auth-action`. Restructure the
  two-phase draft-release flow so tagging can't leave crates.io/APT silently
  unpublished. Add macOS release artifacts (brew tap currently builds from
  source).
- Coverage: make the llvm-cov job blocking once it proves stable (it kept
  `continue-on-error: true` at introduction).
- Lint debt: `cargo clippy --all-targets -- -D warnings` fails in `tests/`
  (accumulated `unwrap_used` etc. — CI only lints lib+bin). Clean up, then add
  `--all-targets` to the CI clippy job so it can't regress.
- criterion is held at 0.7 because 0.8 declares `rust-version = 1.86` — bump
  together with the next MSRV raise.

## Stage 4 — API cleanup & modernization (1 PR, minor release v0.8.0)

Bundle the breaking changes:

- Edition 2021 → 2024 (unblocked: `env::set_var` signaling was removed in #26);
  consider raising MSRV 1.85 → 1.86+ at the same time (unblocks criterion 0.8).
- `#[non_exhaustive]` on public enums that will grow (`TracerouteError`,
  `SegmentType`, `ProbeProtocol`, `SocketMode`, `IpVersion`, error enums) —
  prerequisite for adding IPv6/TCP variants non-breakingly later.
- Remove dead/duplicate public surface: unused `Caches` (`src/caches.rs`),
  duplicate `TimingConfig` (`src/config/timing.rs` vs `src/traceroute/config.rs`),
  duplicate `ProbeInfo`/`ProbeResponse` (`src/socket/mod.rs` vs `src/probe.rs`);
  make `Ftr.services` non-pub; narrow `pub mod socket`/`probe`.
- `TracerouteConfigBuilder::build()` → typed `ConfigError` instead of `String`.

## Stage 5 — Performance & reliability (2 PRs)

- Replace 1ms busy-poll receive loops (`linux.rs`, `macos.rs`, `bsd.rs`) with
  tokio `AsyncFd` readiness — the dominant avoidable CPU cost; also fixes
  detached receiver tasks outliving the trace (tie receivers to the engine's
  `JoinSet`), removes `env::var("CI")` reads inside poll loops, and the
  per-packet throwaway struct allocations.
- Consider shared-socket receive demux instead of socket-per-probe. Unique
  ICMP identifier per concurrent socket, validated on Echo Reply AND on the id
  embedded in Time Exceeded/Unreachable payloads (see `docs/IPV6_DESIGN.md` —
  mandatory for v6 on Darwin, and SwiftFTR's 0.8.0 v4 regression).
- Drop redundant double-locking: outer `tokio::RwLock` around internally
  locked `AsnCache`/`RdnsCache`; make `RdnsCache::get` not take a write lock
  per read.
- Testing hardening: proptest + cargo-fuzz targets for `src/socket/icmp.rs`
  (reject IHL < 5 while at it) and the DNS parser; unit tests for the `unsafe`
  `recvmsg`/CMSG path (linux) and Windows reply-struct reinterpret; gate live-
  network tests behind an env var and serialize them (SwiftFTR's
  `NetworkTestGate` pattern) instead of letting them flake CI.

## Stage 6 — IPv6 support (release train, closes issue #22)

Design and macOS kernel behavior are validated — see `docs/IPV6_DESIGN.md`
(spikes in `examples/spike_*.rs`, PR #27). Key validated facts: unprivileged
DGRAM ICMPv6 on macOS receives Time Exceeded directly (no root needed, unlike
v4); Darwin does NOT demux v6 replies by echo identifier, so userspace id
filtering is mandatory; `ICMP6_FILTER` works via raw `setsockopt` (constant 18
from the macOS SDK, absent from libc/socket2); kernel computes ICMPv6
checksums on DGRAM; STUN v6 and Cymru `origin6` ASN lookups verified live.

Remaining before integration:
- Validate Linux (do ping sockets rewrite ids? filter semantics inverted?),
  Windows (`Icmp6SendEcho2`), and BSD behavior — run the spikes there
  (Parallels VMs / trogdor; GitHub cloud runners have no public IPv6, so live
  v6 tests must be env-gated).
- Root-mode RAW-vs-DGRAM comparison on macOS: `sudo cargo run --example
  spike_traceroute6` (spike auto-detects euid 0).

Bundle v6 trace + v6 ASN enrichment in one release (each is a half-feature
alone); STUN v6 can trail. Contracts (from SwiftFTR, full list in the design
doc): canonical `inet_ntop`-stable address strings; never strip `%zone` from
link-local; single family-agnostic entry point; family in error *context*, not
error type; `--preferred-family`/auto selection with `AI_V4MAPPED` for NAT64.

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
