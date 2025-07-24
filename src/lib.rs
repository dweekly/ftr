//! Fast TraceRoute (ftr) - A parallel traceroute implementation
//!
//! This library provides the core functionality for performing
//! traceroute operations using multiple protocols and socket types.

pub mod socket;

// Re-export core types for library users
pub use socket::factory::{create_probe_socket, create_probe_socket_with_mode};
pub use socket::{IpVersion, ProbeMode, ProbeProtocol, SocketMode};
