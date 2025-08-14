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
//! use ftr::{Ftr, TracerouteConfig};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create an Ftr instance
//!     let ftr = Ftr::new();
//!     
//!     // Simple trace with defaults
//!     let result = ftr.trace("google.com").await?;
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
//! use ftr::{Ftr, TracerouteConfigBuilder, ProbeProtocol};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let ftr = Ftr::new();
//!     
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
//!     let result = ftr.trace_with_config(config).await?;
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
//! use ftr::{Ftr, TracerouteError};
//!
//! let ftr = Ftr::new();
//! match ftr.trace("example.com").await {
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
pub mod caches;
pub mod config;
pub mod services;
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
pub use socket::{IpVersion, ProbeMode, ProbeProtocol, SocketMode};
pub use traceroute::{
    trace, trace_with_config, AsnInfo, ClassifiedHopInfo, IspInfo, RawHopInfo, SegmentType,
    TimingConfig, Traceroute, TracerouteConfig, TracerouteConfigBuilder, TracerouteError,
    TracerouteProgress, TracerouteResult,
};

// Re-export async API
pub use traceroute::async_api;

use services::Services;

/// Main handle for the Ftr library
///
/// The `Ftr` struct owns all services needed for traceroute operations.
/// This design allows for multiple independent instances with isolated state,
/// improving testability and enabling concurrent operations.
///
/// # Examples
///
/// ```no_run
/// use ftr::Ftr;
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let ftr = Ftr::new();
///     let result = ftr.trace("google.com").await?;
///     
///     for hop in result.hops {
///         println!("Hop {}: {:?}", hop.ttl, hop.addr);
///     }
///     
///     Ok(())
/// }
/// ```
pub struct Ftr {
    /// The services container for direct access to individual services
    pub services: Services,
}

impl Ftr {
    /// Create a new Ftr instance with fresh services
    pub fn new() -> Self {
        Self {
            services: Services::new(),
        }
    }

    /// Create a new Ftr instance with optional pre-initialized caches
    ///
    /// Any cache not provided will be created fresh.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use ftr::Ftr;
    ///
    /// // With all fresh caches
    /// let ftr = Ftr::with_caches(None, None, None);
    ///
    /// // With a pre-populated ASN cache
    /// let asn_cache = ftr::asn::cache::AsnCache::new();
    /// // ... populate cache ...
    /// let ftr = Ftr::with_caches(Some(asn_cache), None, None);
    /// ```
    pub fn with_caches(
        asn_cache: Option<crate::asn::cache::AsnCache>,
        rdns_cache: Option<crate::dns::cache::RdnsCache>,
        stun_cache: Option<crate::public_ip::stun_cache::StunCache>,
    ) -> Self {
        // Create services with the provided caches
        let services = Services::with_caches(asn_cache, rdns_cache, stun_cache);

        Self { services }
    }

    /// Run a traceroute to the specified target with default configuration
    ///
    /// This is a convenience method equivalent to creating a default
    /// [`TracerouteConfig`] with the target and calling [`trace_with_config`].
    ///
    /// # Arguments
    ///
    /// * `target` - The target hostname or IP address
    ///
    /// # Returns
    ///
    /// A [`TracerouteResult`] containing the trace results, or a [`TracerouteError`]
    /// if the trace fails.
    pub async fn trace(&self, target: &str) -> Result<TracerouteResult, TracerouteError> {
        let config = TracerouteConfig::builder()
            .target(target)
            .build()
            .map_err(TracerouteError::ConfigError)?;
        self.trace_with_config(config).await
    }

    /// Run a traceroute with custom configuration
    ///
    /// # Arguments
    ///
    /// * `config` - The traceroute configuration
    ///
    /// # Returns
    ///
    /// A [`TracerouteResult`] containing the trace results, or a [`TracerouteError`]
    /// if the trace fails.
    pub async fn trace_with_config(
        &self,
        config: TracerouteConfig,
    ) -> Result<TracerouteResult, TracerouteError> {
        // Use the services-aware implementation
        traceroute::async_api::trace_with_services(config, &self.services).await
    }

    /// Look up ASN information for an IP address
    ///
    /// This is a convenience method that provides direct access to the ASN
    /// lookup service without needing to interact with `Arc<RwLock>`.
    ///
    /// Note: Currently only IPv4 is supported. IPv6 addresses will return
    /// an error.
    ///
    /// # Arguments
    ///
    /// * `ip` - The IP address to look up
    ///
    /// # Returns
    ///
    /// ASN information including AS number, prefix, country, and organization name
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use ftr::Ftr;
    /// use std::net::IpAddr;
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///     let ftr = Ftr::new();
    ///     let ip: IpAddr = "8.8.8.8".parse()?;
    ///     let asn_info = ftr.lookup_asn(ip).await?;
    ///     println!("AS{}: {}", asn_info.asn, asn_info.name);
    ///     Ok(())
    /// }
    /// ```
    pub async fn lookup_asn(
        &self,
        ip: std::net::IpAddr,
    ) -> Result<crate::traceroute::AsnInfo, crate::asn::AsnLookupError> {
        self.services.asn.lookup(ip).await
    }

    /// Look up the hostname for an IP address
    ///
    /// This is a convenience method that provides direct access to the reverse
    /// DNS lookup service without needing to interact with `Arc<RwLock>`.
    ///
    /// # Arguments
    ///
    /// * `ip` - The IP address to look up
    ///
    /// # Returns
    ///
    /// The hostname associated with the IP address
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use ftr::Ftr;
    /// use std::net::IpAddr;
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///     let ftr = Ftr::new();
    ///     let ip: IpAddr = "8.8.8.8".parse()?;
    ///     let hostname = ftr.lookup_rdns(ip).await?;
    ///     println!("{} -> {}", ip, hostname);
    ///     Ok(())
    /// }
    /// ```
    pub async fn lookup_rdns(
        &self,
        ip: std::net::IpAddr,
    ) -> Result<String, crate::dns::ReverseDnsError> {
        self.services.rdns.lookup(ip).await
    }

    /// Get the public IP address of this machine
    ///
    /// This is a convenience method that uses STUN protocol to detect
    /// the public IP address as seen from the internet.
    ///
    /// # Returns
    ///
    /// The public IP address
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use ftr::Ftr;
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///     let ftr = Ftr::new();
    ///     let public_ip = ftr.get_public_ip().await?;
    ///     println!("Public IP: {}", public_ip);
    ///     Ok(())
    /// }
    /// ```
    pub async fn get_public_ip(
        &self,
    ) -> Result<std::net::IpAddr, crate::public_ip::providers::PublicIpError> {
        self.services.stun.get_public_ip().await
    }

    /// Clear all caches across all services
    ///
    /// This removes all cached data, forcing fresh lookups for all
    /// subsequent queries. Useful for testing or when cached data
    /// may be stale.
    pub async fn clear_all_caches(&self) {
        self.services.clear_all_caches().await;
    }
}

impl Default for Ftr {
    fn default() -> Self {
        Self::new()
    }
}
