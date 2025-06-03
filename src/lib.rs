//! Fast TraceRoute (ftr) - A parallel traceroute implementation
//! 
//! This library provides the core functionality for performing
//! traceroute operations using multiple protocols and socket types.

pub mod socket;

// Re-export core types for library users
pub use socket::{ProbeMode, ProbeProtocol, IpVersion};