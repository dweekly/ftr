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
//!         .protocol(ProbeProtocol::TCP)
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
//! # Modules
//!
//! - [`asn`]: ASN (Autonomous System Number) lookup functionality
//! - [`dns`]: Reverse DNS lookup with caching
//! - [`public_ip`]: Public IP detection and ISP information
//! - [`socket`]: Low-level socket implementations for different probe types
//! - [`traceroute`]: Core traceroute engine and high-level API

#![allow(clippy::uninlined_format_args)]

pub mod asn;
pub mod dns;
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
    Traceroute, TracerouteConfig, TracerouteConfigBuilder, TracerouteError, TracerouteProgress,
    TracerouteResult,
};
