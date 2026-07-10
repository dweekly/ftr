//! Error types for traceroute operations

use thiserror::Error;

/// Errors from validating a [`TracerouteConfig`](crate::TracerouteConfig)
///
/// Returned by [`TracerouteConfigBuilder::build`](crate::TracerouteConfigBuilder::build)
/// and [`TracerouteConfig::validate`](crate::TracerouteConfig::validate).
///
/// This enum is `#[non_exhaustive]`: new validation rules may be added in
/// minor releases, so downstream matches must include a wildcard arm.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum ConfigError {
    /// Neither `target` nor `target_ip` was provided
    #[error("Target must be specified")]
    MissingTarget,

    /// `start_ttl` must be at least 1
    #[error("start_ttl must be at least 1")]
    InvalidStartTtl,

    /// `max_hops` must be greater than or equal to `start_ttl`
    #[error("max_hops ({max_hops}) must be greater than or equal to start_ttl ({start_ttl})")]
    MaxHopsLessThanStartTtl {
        /// The configured starting TTL
        start_ttl: u8,
        /// The configured maximum hop count
        max_hops: u8,
    },

    /// `probe_timeout` must be greater than zero
    #[error("probe_timeout must be greater than 0")]
    ZeroProbeTimeout,

    /// `queries_per_hop` must be at least 1
    #[error("queries_per_hop must be at least 1")]
    ZeroQueriesPerHop,
}

/// Errors that can occur during traceroute operations
///
/// This enum is `#[non_exhaustive]`: new error variants may be added in
/// minor releases, so downstream matches must include a wildcard arm.
#[derive(Debug, Error)]
#[non_exhaustive]
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
    ConfigError(#[from] ConfigError),

    /// Failed to send probe packet
    #[error("Failed to send probe: {0}")]
    ProbeSendError(String),

    /// General traceroute operation error
    #[error("{0}")]
    Other(String),
}
