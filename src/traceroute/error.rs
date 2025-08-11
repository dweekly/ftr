//! Error types for traceroute operations

use thiserror::Error;

/// Errors that can occur during traceroute operations
#[derive(Debug, Error)]
pub enum TracerouteError {
    /// Socket creation failed due to insufficient permissions
    ///
    /// This error provides structured information about what permissions
    /// are needed and how to obtain them.
    #[error("Insufficient permissions: {required}")]
    InsufficientPermissions {
        /// Description of required permissions (e.g., "root or CAP_NET_RAW")
        required: String,
        /// Suggested remedy (e.g., "Run with sudo or use --udp mode")
        suggestion: String,
    },

    /// Socket creation failed for other reasons
    #[error("Failed to create socket: {0}")]
    SocketError(String),

    /// DNS resolution failed
    ///
    /// The target hostname could not be resolved to an IP address.
    #[error("Failed to resolve host: {0}")]
    ResolutionError(String),

    /// Feature not yet implemented
    ///
    /// The requested feature (e.g., TCP traceroute) is not yet available.
    #[error("{feature} is not yet implemented")]
    NotImplemented {
        /// Description of the unimplemented feature
        feature: String,
    },

    /// IPv6 targets are not yet supported
    #[error("IPv6 targets are not yet supported")]
    Ipv6NotSupported,

    /// Invalid configuration provided
    #[error("Invalid configuration: {0}")]
    ConfigError(String),

    /// Failed to send probe packet
    #[error("Failed to send probe: {0}")]
    ProbeSendError(String),

    /// General traceroute operation error
    #[error("{0}")]
    Other(String),
}
