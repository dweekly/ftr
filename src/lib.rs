//! Fast TraceRoute (ftr) - A parallel traceroute implementation
//!
//! This library provides high-performance traceroute functionality with support for
//! multiple protocols, parallel probing, and rich network information enrichment.
//!
//! # Features
//!
//! - **Multiple protocols**: ICMP, UDP, and TCP traceroute support
//! - **Parallel probing**: Send multiple probes simultaneously for faster results
//! - **Rich information**: Automatic ASN lookup, reverse DNS, and ISP detection
//! - **Flexible socket modes**: Raw sockets, DGRAM sockets, or unprivileged UDP
//! - **Cross-platform**: Works on Linux, macOS, Windows, and BSD systems
//! - **Caching**: Built-in caching for DNS and ASN lookups to improve performance
//!
//! # Quick Start
//!
//! ```no_run
//! use ftr::{trace, TracerouteConfig};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Simple trace with defaults
//!     let result = trace("google.com").await?;
//!     
//!     for hop in result.hops {
//!         println!("Hop {}: {:?}", hop.ttl, hop.addr);
//!     }
//!     
//!     Ok(())
//! }
//! ```
//!
//! # Advanced Usage
//!
//! ```no_run
//! use ftr::{TracerouteConfigBuilder, ProbeProtocol};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let config = TracerouteConfigBuilder::new()
//!         .target("1.1.1.1")
//!         .protocol(ProbeProtocol::Tcp)
//!         .port(443)
//!         .max_hops(20)
//!         .queries(3)
//!         .parallel_probes(32)
//!         .enable_asn_lookup(true)
//!         .enable_rdns(true)
//!         .build()?;
//!     
//!     let result = ftr::trace_with_config(config).await?;
//!     println!("Trace complete: {} hops", result.hops.len());
//!     
//!     Ok(())
//! }
//! ```
//!
//! # Error Handling
//!
//! The library provides structured error types through the [`TracerouteError`] enum,
//! allowing for programmatic error handling without string parsing:
//!
//! ```no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use ftr::{trace, TracerouteError};
//!
//! match trace("example.com").await {
//!     Ok(result) => println!("Success! Found {} hops", result.hop_count()),
//!     
//!     // Permission errors include structured information
//!     Err(TracerouteError::InsufficientPermissions { required, suggestion }) => {
//!         eprintln!("Permission denied: {}", required);
//!         eprintln!("Try: {}", suggestion);
//!     }
//!     
//!     // Feature not implemented errors
//!     Err(TracerouteError::NotImplemented { feature }) => {
//!         eprintln!("{} is not yet implemented", feature);
//!         // Could fall back to supported features
//!     }
//!     
//!     // Other structured errors
//!     Err(TracerouteError::Ipv6NotSupported) => {
//!         eprintln!("IPv6 targets are not yet supported");
//!     }
//!     Err(TracerouteError::ResolutionError(msg)) => {
//!         eprintln!("DNS resolution failed: {}", msg);
//!     }
//!     Err(e) => eprintln!("Error: {}", e),
//! }
//! # Ok(())
//! # }
//! ```
//!
//! See [`TracerouteError`] for all error variants and the `examples/error_handling.rs`
//! example for comprehensive error handling patterns.
//!
//! # Modules
//!
//! - [`asn`]: ASN (Autonomous System Number) lookup functionality
//! - [`dns`]: Reverse DNS lookup with caching
//! - [`public_ip`]: Public IP detection and ISP information
//! - [`socket`]: Low-level socket implementations for different probe types
//! - [`traceroute`]: Core traceroute engine and high-level API

#![allow(clippy::uninlined_format_args)]

pub mod asn;
pub mod config;
/// Simple debug print macro for conditional debug output
#[macro_export]
macro_rules! debug_print {
    ($level:expr, $($arg:tt)*) => {
        #[cfg(debug_assertions)]
        {
            eprintln!("[DEBUG {}] {}", $level, format!($($arg)*));
        }
    };
}

/// Macro for timing traces in very verbose mode
#[macro_export]
macro_rules! trace_time {
    ($verbose:expr, $($arg:tt)*) => {
        if $verbose >= 2 {
            eprintln!("[TIMING {:?}] {}", std::time::Instant::now(), format!($($arg)*));
        }
    };
}
pub mod dns;
pub mod enrichment;
#[cfg(feature = "async")]
pub mod probe;
pub mod public_ip;
pub mod socket;
pub mod traceroute;

#[cfg(test)]
mod tests;

// Re-export core types for library users
pub use socket::factory::{
    create_probe_socket, create_probe_socket_with_mode, create_probe_socket_with_options,
};
pub use socket::{IpVersion, ProbeMode, ProbeProtocol, SocketMode};
pub use traceroute::{
    trace, trace_with_config, AsnInfo, ClassifiedHopInfo, IspInfo, RawHopInfo, SegmentType,
    TimingConfig, Traceroute, TracerouteConfig, TracerouteConfigBuilder, TracerouteError,
    TracerouteProgress, TracerouteResult,
};

// Re-export async API when feature is enabled
#[cfg(feature = "async")]
pub use traceroute::async_api;
