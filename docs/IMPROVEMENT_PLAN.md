# ftr Improvement Plan

Plan from a full-project review (code, docs, CI, and a feature-gap analysis
against SwiftFTR 0.13.0) against Rust best practices as of mid-2026. Sections
are stack-ranked — top is next; each is a shippable unit. Delete sections as
they merge (git has the history).

Context: ftr is in maintenance mode (SwiftFTR is the primary macOS client), but
has external users (GitHub stars, crates.io, APT repo, one open issue — #22
requesting IPv6). The v0.8.0 release (PRs #23–#35) covered docs accuracy,
correctness fixes, dependency updates, CI/supply-chain hardening, IPv6
validation spikes, the breaking API cleanup, edition 2024, system DNS
resolvers, and the tests lint-debt payoff; what remains is below.

## Follow-ups from landed work (small, independent)

- DNS: TCP fallback on truncated (TC) responses (`DnsError::Truncated`
  exists; nothing retries over TCP). Windows system-resolver discovery
  (`GetAdaptersAddresses`). Automatic DNS-config change watching to
  complement `dns::refresh_system_dns()` — macOS via `notify(3)` on
  `com.apple.system.SystemConfiguration.dns_configuration` (Chromium's
  approach, <https://issues.chromium.org/issues/40182831>; the c-ares
  maintainers catalog per-platform equivalents in c-ares/c-ares#613),
  Linux via inotify on resolv.conf. `#[non_exhaustive]` on
  `ReverseDnsError`/`DnsRecord` (skipped in #33 to avoid cross-PR
  conflicts).
- Releases: adopt crates.io Trusted Publishing (OIDC) — requires one-time
  configuration on crates.io by the maintainer, then swap the token step in
  `release.yml` for `rust-lang/crates-io-auth-action`. Restructure the
  two-phase draft-release flow so tagging can't leave crates.io/APT silently
  unpublished. Add macOS release artifacts (brew tap currently builds from
  source).
- Coverage: make the llvm-cov job blocking once it proves stable (it kept
  `continue-on-error: true` at introduction).
- criterion is held at 0.7 because 0.8 declares `rust-version = 1.86` — bump
  together with the next MSRV raise.
- Unprivileged macOS traceroute: `macos.rs` only implements raw ICMP
  (root-gated by Darwin), but macOS supports unprivileged `SOCK_DGRAM`
  ICMP — SwiftFTR does full traceroutes without root this way, and the v6
  spike proved DGRAM receives Time Exceeded unprivileged
  (`docs/IPV6_DESIGN.md`). Add a DGRAM fallback like Linux's; falls out
  naturally from IPv6 integration, which needs the DGRAM path anyway.
  Remember Darwin demuxes v4 DGRAM ICMP by identifier (SwiftFTR's 0.8.0
  regression) but does NOT for v6.

## Dependency diet (standing theme + a ladder of PRs)

Maintainer directive (2026-07-17): as an overall theme, reduce the size and
complexity of the dependency tree — SwiftFTR's zero-third-party-deps is the
aspiration. Every new dependency needs justification; prefer hand-rolled
minimal implementations for narrow needs (the 0.7.0 hickory/reqwest/pnet
replacements are the model). Baseline 2026-07-17: **78 transitive crates
from 10 direct** (macOS; Linux adds vendored OpenSSL). Ladder, biggest win
first:

- **Kill ureq + TLS (32 crates, 40% of the tree)**: its sole use is the
  HTTPS public-IP fallback. STUN stays primary (it reflects the probing
  socket's true public mapping). Replace the HTTPS fallback with a STUN
  server (or trivial UDP address-echo) on the Network Weather DigitalOcean
  droplet — infrastructure we control, same protocol, zero TLS. Maintainer
  ruling (2026-07-17): DNS whoami techniques (Akamai/Cloudflare/Google) are
  NOT acceptable — the reported address is the recursive resolver's egress,
  not the client's, whenever queries traverse a forwarding resolver, and
  port-53 interception corrupts even direct queries. (Cloudflare's
  `cdn-cgi/trace` endpoints are useful only if an HTTPS fallback survives.)
  Also removes the vendored-OpenSSL Linux build and the TLS provider
  fragility (a runtime panic lived there until PR #39).
- **getrandom (3 crates)**: only seeds STUN transaction IDs and DNS query
  IDs — `std::hash::RandomState` per-process entropy hashed with a counter
  suffices for these non-crypto IDs (document the security posture: DNS ID
  is anti-spoofing defense-in-depth alongside source-port randomization).
- **ip_network + ip_network_table (3 crates)**: ASN cache longest-prefix
  match over a few hundred prefixes — a sorted-Vec binary search or small
  hand-rolled trie replaces it.
- **serde + serde_json (9 crates incl. proc-macro build deps)**: ftr only
  *serializes* (JSON output); a small hand-rolled JSON emitter with correct
  string escaping covers it. TODO.md already contemplates this.
- **clap (19 crates)**: 16 flags; a minimal parser (or `lexopt`-style
  single-crate) with hand-written --help. Trade-off: loses completions and
  polish — do last, only if the theme still has appetite.
- **thiserror (8 crates, build-time syn/quote)**: mechanical hand-written
  `Display`/`Error` impls. Low value per churn — optional.
- **tokio stays**: the async API is the product; consumers depend on it.

Do NOT batch these with feature work; each rung is its own PR with
before/after `cargo tree` counts in the body.

## Performance & reliability (two PRs)

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

## IPv6: remaining platform + polish work

macOS, Linux, and BSD IPv6 shipped in 0.9.0 (PRs #38–#43). Remaining:

- Windows IPv6 via `Icmp6SendEcho2`, mirroring the v4 `IcmpSendEcho2`
  implementation. Validate live on the `nwx-dell-11` Tailscale box (local
  Parallels is unreliable); also pay down the ~16 dead-code lints visible
  only under a Windows-target `clippy --all-targets` (CI's clippy job runs
  on Ubuntu and never compiles windows.rs — consider a windows-target
  clippy cross-check in CI).
- Open observations: router-originated ICMPv6 Time Exceeded on FreeBSD
  remains unobserved first-hand (CI VM has no external v6); macOS root-mode
  RAW-vs-DGRAM comparison (`sudo cargo run --release --example
  spike_traceroute6`).
- Polish: NAT64/DNS64 handling review (`AI_V4MAPPED`-style synthesis for
  v4 literals on v6-only networks); first-class zone-scoped (`fe80::%if`)
  targets; hop-level zone display.

## Feature ports from SwiftFTR (optional, by appetite)

Stack-ranked by fit for a traceroute tool with external users:

- **Streaming trace API** — `impl Stream<Item = StreamingHop>` emitting hops
   in arrival order with a re-probe phase for rate-limited routers. Best
   library-consumer win; SwiftFTR's `StreamingTrace` is the reference.
- **UDP 5-tuple multipath/ECMP discovery** — ftr on Linux already has
   unprivileged UDP traceroute, so true Dublin/Paris-style flow variation is
   *more* attainable here than it was for SwiftFTR (which shipped ICMP-ID
   variation and documented it under-discovers, deferring UDP to its roadmap).
   A differentiating feature, not just parity.
- **TCP/UDP connectivity probes** — connected-UDP trick (ICMP unreachable
   surfaces as `ECONNREFUSED`, no privileges) and non-blocking TCP connect.
   Small, self-contained.
- **Bufferbloat/RPM testing** — probably out of scope for ftr; it drags in
   HTTP load generation and third-party endpoints. Skip unless a user asks.
