# API Ergonomics Critique and Refined Plan

This document reviews the proposed “Services Container” API refactor for ftr, highlights gaps and risks, and proposes a refined, incremental design that improves ergonomics, performance, and testability.

## Strengths

- Task-centric API: Good shift from cache-centric helpers to intentful methods (`lookup_asn`, `lookup_rdns`, `get_public_ip`).
- Encapsulation: Caching and resolver details are internal — solid separation of concerns.
- Progressive disclosure: Simple defaults with room for advanced configuration.
- Migration plan: Phased approach reduces churn and keeps users unblocked.

## Gaps & Risks

- Locking model: Examples mix blocking `RwLock` with async-style `read().await`. Avoid outer locks on services; keep locking internal and never hold a lock across `.await`.
- Redundant locks: `Arc<RwLock<Service>>` is unnecessary if the service is concurrency-safe. Prefer `Arc<Service>` with interior mutability for caches.
- IPv6 parity: Use `IpAddr` (not `Ipv4Addr`) across services to future-proof IPv6 support.
- Leaky container: `Services` with `pub` fields exposes implementation. Keep it private behind `Ftr` or expose narrow accessors.
- RDNS TTL: Fixed TTL caching is incorrect. Respect DNS TTLs and negative caching (RFC 2308).
- Batch & streaming: Single-item methods only. Batch lookups and `trace_stream` improve throughput and UX.
- Test seams: No traits/injection points to mock DNS/STUN/socket behavior for unit tests.

## Refined Design (Incremental, Drop-in)

- Construction: Add `FtrBuilder` and `ServicesBuilder` for resolvers, timeouts, feature flags (`enrich`, `rdns`, `stun`).
- Service storage: `struct Services { asn: Arc<AsnLookup>, rdns: Arc<RdnsLookup>, stun: Arc<StunClient> }` — no outer locks; keep `Services` private in `Ftr`.
- Service contracts:
  - Use `IpAddr` consistently.
  - Provide `lookup` plus optional `*_batch(&[IpAddr])` variants.
  - Expose `clear_cache` and `cache_stats` for advanced users.
  - Internals use `parking_lot::RwLock` or `DashMap`; never hold a lock across `.await`.
  - RDNS honors DNS TTLs and negative caching.
- Traceroute ergonomics:
  - `trace(config)` returns a structured result.
  - `trace_stream(config)` returns `impl Stream<Item = ProbeEvent>` for incremental UIs/logging.
  - Internally pass `&Services` to the engine but keep it hidden from end users.

## Performance Enhancements

- Batch lookups: `lookup_batch(&[IpAddr]) -> HashMap<IpAddr, Info>` reduces resolver round-trips and enables coalescing.
- Bounded concurrency: Use a `Semaphore` to cap enrichment concurrency and reduce latency tails.
- Caches:
  - ASN: prefix tree + sharded locks or `DashMap` to reduce contention.
  - RDNS: TTL-aware entries, negative cache, and `Arc<str>` to minimize allocations.
- Zero-cost flags: When `--no-enrich/--no-rdns`, don’t initialize those services.

## Testability Improvements

- Traits for injection: Define `DnsResolver` and `StunProvider` traits used by services; inject fakes in tests.
- Deterministic unit tests: Feature flag to disable network; use recorded fixtures for RDNS/ASN; simple STUN stub.
- Property tests: TTL stepping, hop aggregation, and cache eviction/refresh boundaries.
- Doc tests: Small no-network examples guarded by `cfg(doc)` so docs.rs builds cleanly.

## Developer Ergonomics

- Prelude: `ftr::prelude` re-exports `Ftr`, `TracerouteConfig`, and common types.
- Examples: Keep README and `docs/LIBRARY_USAGE.md` in sync; add `trace_stream` example.
- Global helper (optional): `ftr::global() -> &'static Ftr` via `OnceCell` for quick scripts (document test caveats).
- Stable JSON: Version JSON output; publish schema for downstream consumers.

## Concurrency Pattern (Concrete Tweaks)

- Store services: `Arc<Service>` without outer locks.
- Inside services: Use `parking_lot::RwLock` or `DashMap`; read -> drop lock -> fetch -> write; never `.await` while locked.
- Ftr methods: Thin async wrappers, e.g., `self.services.asn.lookup(ip).await`.

## Migration & Stability

- Deprecate cleanly: Use `#[deprecated(note = "...")]` with clear migration notes and links.
- Aliases: Temporary type aliases (e.g., `type AsnCache = AsnLookup`) ease upgrades.
- CI guardrails: Ensure examples compile only with the new API; add before/after benchmarks to detect regressions.

## Nice-to-Haves

- Metrics: `tracing` spans for probes; optional `metrics` for `cache_hits`, `misses`, per-hop latency.
- Warm caches: Opt-in cache snapshot load/save for long-running daemons.
- Rate limiting: Token bucket for probes to balance speed and device friendliness.

## Actionable Next Steps

- Replace `Arc<RwLock<Service>>` with `Arc<Service>` and remove `.read().await` at the API boundary.
- Switch service inputs to `IpAddr`.
- Add `FtrBuilder`/`ServicesBuilder` with defaults and feature toggles.
- Implement RDNS TTL-aware, negative-caching store and tests.
- Add `trace_stream` and `ProbeEvent`.
- Introduce `DnsResolver`/`StunProvider` traits and wire fakes in unit tests.
- Update README and `docs/LIBRARY_USAGE.md`; add doctests.

