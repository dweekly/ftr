//! Fast TraceRoute (ftr) - A parallel traceroute implementation
//!
//! This library provides the core functionality for performing
//! traceroute operations using multiple protocols and socket types.

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
