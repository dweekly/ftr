# Modernization Plan

This document outlines the plan to modernize ftr's codebase, reduce supply chain risk, and adopt mid-2026 Rust best practices.

## Phase 1: Naming Cleanup (No Dependency Changes)

Remove redundant "async" prefixes from module names and types. Since v0.4.0 removed all sync code, these are just noise.

### Renames

| Current | New |
|---------|-----|
| `src/traceroute/async_api.rs` | `src/traceroute/api.rs` |
| `src/traceroute/async_engine.rs` | `src/traceroute/engine.rs` |
| `src/traceroute/fully_parallel_async_engine.rs` | `src/traceroute/parallel_engine.rs` |
| `src/socket/async_factory.rs` | `src/socket/factory.rs` |
| `src/socket/async_trait.rs` | `src/socket/traits.rs` |
| `src/socket/linux_async.rs` | `src/socket/linux.rs` |
| `src/socket/macos_async.rs` | `src/socket/macos.rs` |
| `src/socket/bsd_async.rs` | `src/socket/bsd.rs` |
| `src/socket/windows_async_tokio.rs` | `src/socket/windows.rs` |
| `src/enrichment/async_service.rs` | `src/enrichment/service.rs` |
| `AsyncProbeSocket` (trait) | `ProbeSocket` |
| `AsyncEnrichmentService` (struct) | `EnrichmentService` |
| `FullyParallelAsyncEngine` (struct) | `ParallelEngine` |

This is a mechanical refactor with no behavior change. Use `git mv` for files, then search-and-replace for type names. Library re-exports in `lib.rs` ensure no public API breakage.

## Phase 2: Remove `async-trait` Dependency

**Why**: Native `async fn` in traits is stable since Rust 1.75. Our MSRV is 1.82.

**What changes**:
- Remove `#[async_trait]` attribute from `AsyncProbeSocket` trait and all impls
- Add `Send` bound on the return type where needed: `async fn send_probe(...) -> ... + Send`
- Remove `async-trait` from `Cargo.toml`

**Risk**: Low. This is a proc-macro removal — the generated code is equivalent.

## Phase 3: Remove `futures` Dependency

**Why**: The only usage is `FuturesUnordered` + `StreamExt` in 3 files. Tokio's `JoinSet` provides the same capability.

**What changes**:
- Replace `FuturesUnordered` with `tokio::task::JoinSet` in:
  - `src/enrichment/async_service.rs`
  - `src/traceroute/async_engine.rs`
  - `src/traceroute/fully_parallel_async_engine.rs`
- Remove `futures` from `Cargo.toml`

**Risk**: Low. `JoinSet` spawns tasks on the Tokio runtime rather than polling futures directly. Behavior is equivalent for our use case (fire-and-gather concurrent work).

## Phase 4: Remove `anyhow` — Use Structured Errors Everywhere

**Why**: The library already has `TracerouteError` via `thiserror`. `anyhow` is used inconsistently alongside it.

**What changes**:
- Replace `anyhow::Result` with `Result<T, TracerouteError>` in library code
- Keep `anyhow` only in `main.rs` for CLI error formatting, or remove it entirely and use `TracerouteError` with a `Display` impl
- Audit all `anyhow::anyhow!()` and `context()` calls

**Risk**: Medium. Requires careful error type propagation.

## Phase 5: Replace `reqwest` with Lightweight HTTP

**Why**: `reqwest` is the heaviest dependency, pulling in hyper, tower, http, http-body, native-tls, and more. ftr makes simple HTTP GET requests to a single WHOIS API endpoint.

**Options**:
1. **`ureq`** — Blocking HTTP client, use inside `spawn_blocking`. Minimal deps. No async runtime coupling.
2. **`minreq`** — Even smaller, ~1000 lines. Supports HTTPS with `native-tls` feature.
3. **Manual HTTP over `tokio::net::TcpStream`** + `native-tls` — Zero HTTP library deps but more code to maintain.

**Recommendation**: `ureq` — well-maintained, tiny footprint, handles HTTPS. Use `spawn_blocking` to call it from async context.

**Risk**: Medium. Need to verify HTTPS cert validation, timeout handling, and redirect behavior match current behavior.

## Phase 6: Replace `pnet` with Manual ICMP Parsing

**Why**: `pnet` is a large networking library. ftr uses it only for:
- ICMP echo request construction (`MutableEchoRequestPacket`)
- ICMP packet parsing (`IcmpPacket`, `IcmpTypes`)
- ICMP echo reply parsing (`echo_reply`)
- IP header parsing

**What changes**:
- Define small structs for ICMP header (8 bytes) and IP header (20 bytes)
- Implement checksum calculation (RFC 1071 — ~10 lines)
- Manual packet construction and parsing with byte slices

**Risk**: Medium. Packet parsing is security-sensitive — must be carefully tested. But the formats are simple and well-specified.

## Phase 7: Remove `ipnet` — Use `ip_network` Only

**Why**: Both `ipnet` and `ip_network` / `ip_network_table` provide IP network types. Consolidate to one.

**What changes**:
- Replace `ipnet::Ipv4Net` usage in `src/traceroute.rs`, `src/asn/lookup.rs`, `src/asn/cache.rs` with `ip_network::Ipv4Network`
- Remove `ipnet` from `Cargo.toml`

**Risk**: Low. Simple type substitution.

## Dependency Roadmap Summary

| Phase | Removes | Adds | Net Change |
|-------|---------|------|------------|
| 1. Naming | — | — | 0 |
| 2. async-trait | `async-trait` | — | -1 |
| 3. futures | `futures` | — | -1 |
| 4. anyhow | `anyhow` | — | -1 |
| 5. reqwest | `reqwest` (+ hyper, tower, http, etc.) | `ureq` | -15+ transitive |
| 6. pnet | `pnet` | — | -1 |
| 7. ipnet | `ipnet` | — | -1 |

**Final direct dependencies** (target): `tokio`, `socket2`, `clap`, `serde`, `serde_json`, `thiserror`, `hickory-resolver`, `ureq`, `ip_network`, `ip_network_table`, `getrandom`, plus platform-specific `libc`/`windows-sys`.

That's 12 direct dependencies, down from 18 today. Transitive dependency count drops significantly — especially removing reqwest (which alone brings ~50 transitive deps).

## Version Considerations

After completing these changes, this warrants a **v0.7.0** release since:
- Module renames are breaking for anyone importing internal paths
- `anyhow` removal changes error types in some library functions
- Dependency overhaul benefits from a clean version boundary
