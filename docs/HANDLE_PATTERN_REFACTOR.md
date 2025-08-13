# High-Level Plan: Refactor to Eliminate Global Caches (Handle Pattern)

## Goal

The primary goal of this refactoring is to eliminate the use of global static caches (`ASN_CACHE`, `RDNS_CACHE`, `STUN_CACHE`) throughout the `ftr` library. Instead, we will introduce a top-level `Ftr` struct that will own all necessary caches and resources, acting as a self-contained instance for all library operations.

## Motivation

This change is driven by several key benefits:

1.  **Improved Testability:** By removing global state, tests can be run in complete isolation without interfering with each other. This eliminates flakiness and simplifies test setup and teardown.
2.  **Enhanced Flexibility:** Users will be able to instantiate multiple `Ftr` instances, each with its own independent set of caches and configurations. This is crucial for applications requiring different tracing behaviors or concurrent operations without shared side effects.
3.  **Clear Ownership and Lifetimes:** The ownership of caches and other resources will be explicitly managed by the `Ftr` struct, making resource management more predictable and preventing potential memory leaks or unexpected behavior.
4.  **Cleaner API:** The library's public API will become more object-oriented and intuitive, with operations performed on an `Ftr` instance rather than through free-standing functions that implicitly rely on global state.
5.  **Preparation for Future Features:** A clean, non-global architecture will make it easier to introduce new features and extend the library in the future.

## High-Level Steps

This refactoring will involve changes across multiple modules. It is a breaking change to the public API and should be considered for a major version bump (e.g., 0.4.0 to 1.0.0).

### 1. Create the Top-Level `Ftr` Struct

*   Define a new `pub struct Ftr` in `src/lib.rs`.
*   This struct will hold instances of `AsnCache`, `RdnsCache`, and `StunCache`.
*   Implement `Ftr::new()` to create a default instance with new caches.
*   Consider `Ftr::with_caches()` for advanced users who want to inject custom or shared cache instances.

### 2. Refactor Public API Functions into `Ftr` Methods

*   The existing `pub async fn trace(...)` and `pub async fn trace_with_config(...)` functions in `src/lib.rs` will be removed.
*   Equivalent `pub async fn trace(...)` and `pub async fn trace_with_config(...)` methods will be added to the `Ftr` struct.
*   These methods will internally call a new, lower-level function (e.g., `traceroute::async_api::run_traceroute_with_caches`) that accepts the caches as arguments.

### 3. Propagate Cache Instances Through the Call Stack

This is the most extensive part of the refactoring. Any function that currently relies on a global static cache will need to be updated:

*   **`src/traceroute/async_api.rs`**: The `AsyncTraceroute::run` method will be updated to accept `&AsnCache`, `&RdnsCache`, and `&StunCache` as arguments. It will then pass these down to the `FullyParallelAsyncEngine`.
*   **`src/traceroute/fully_parallel_async_engine.rs`**: The `FullyParallelAsyncEngine` struct will be updated to store references (or `Arc`s) to the caches. Its `new` method will accept these caches, and its `run` and `build_result` methods will use them for enrichment and ISP detection.
*   **`src/public_ip/mod.rs`**: Functions like `detect_isp_stun`, `detect_isp`, `detect_isp_with_default_resolver`, and `detect_isp_from_ip` will be updated to accept `&StunCache`, `&AsnCache`, and `&RdnsCache` as arguments.
*   **`src/public_ip/stun.rs`**: Functions like `get_public_ip_stun` and `get_public_ip_stun_with_fallback` will be updated to accept `&StunCache`.
*   **`src/public_ip/stun_cache.rs`**: The `prewarm_stun_cache` function will be updated to accept a `&StunCache` instance.
*   **`src/asn/lookup.rs`**: The `lookup_asn` function will be updated to accept a `&AsnCache`.
*   **`src/dns/reverse.rs`**: The `reverse_dns_lookup` function will be updated to accept a `&RdnsCache`.

### 4. Remove Global Static Caches

*   Once all call sites have been updated, the `pub static ASN_CACHE`, `pub static RDNS_CACHE`, and `pub static STUN_CACHE` declarations will be removed from their respective `cache.rs` files.

### 5. Update `src/main.rs` (CLI Entry Point)

*   The `main` function will need to instantiate `Ftr::new()` at the beginning.
*   All subsequent calls to `trace` or `trace_with_config` will be made on this `Ftr` instance (e.g., `ftr_instance.trace(...)`).

### 6. Update Tests

*   All existing tests will need to be updated to instantiate `Ftr::new()` and call its methods. This will ensure that all tests run in isolation and verify the new API.
*   Remove any remaining `#[serial]` attributes that might have been missed or were previously necessary due to global state.

## Expected Impact

*   **Breaking Change:** This refactoring will introduce breaking changes to the library's public API, requiring users to adapt their code. This is why it's suitable for a 0.4.0 release (or 1.0.0 if deemed a major architectural shift).
*   **Increased Code Clarity:** The flow of data and dependencies will be much clearer.
*   **More Robustness:** The library will be inherently more thread-safe and less prone to unexpected interactions between different parts of an application.
*   **Improved Performance (Testing):** Test suites will run faster and more reliably due to true isolation.