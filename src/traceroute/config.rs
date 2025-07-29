//! Configuration types for traceroute operations

use crate::socket::{ProbeProtocol, SocketMode};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::time::Duration;

/// Internal timing configuration for traceroute engine
///
/// These are internal delays used for various operations. Most users should not need
/// to modify these values. The defaults have been chosen for optimal performance
/// while maintaining reliability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingConfig {
    /// Receiver thread polling interval (default: 100ms)
    /// How often the receiver thread checks for incoming packets
    pub receiver_poll_interval: Duration,

    /// Main wait loop polling interval (default: 10ms)
    /// How often we check if all probes have completed
    pub main_loop_poll_interval: Duration,

    /// Enrichment completion wait time (default: 100ms)
    /// How long to wait for ASN/rDNS lookups to complete after all probes finish
    pub enrichment_wait_time: Duration,

    /// Socket read timeout (default: 100ms)
    /// Maximum time to wait for a single socket read operation
    pub socket_read_timeout: Duration,

    /// UDP socket retry delay (default: 10ms)
    /// Delay between retries when UDP socket operations fail
    pub udp_retry_delay: Duration,
}

impl Default for TimingConfig {
    fn default() -> Self {
        Self {
            receiver_poll_interval: Duration::from_millis(100),
            main_loop_poll_interval: Duration::from_millis(10),
            enrichment_wait_time: Duration::from_millis(100),
            socket_read_timeout: Duration::from_millis(100),
            udp_retry_delay: Duration::from_millis(10),
        }
    }
}

/// Configuration for a traceroute operation
///
/// This struct contains all the parameters needed to control a traceroute operation.
/// Use [`TracerouteConfigBuilder`] to create instances with a fluent API.
///
/// # Examples
///
/// ```
/// use ftr::TracerouteConfig;
/// use std::time::Duration;
///
/// let config = TracerouteConfig::builder()
///     .target("google.com")
///     .max_hops(20)
///     .probe_timeout(Duration::from_secs(2))
///     .build()
///     .unwrap();
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracerouteConfig {
    /// Target hostname or IP address
    pub target: String,
    /// Resolved target IP address (optional pre-resolution)
    pub target_ip: Option<IpAddr>,
    /// Starting TTL value (default: 1)
    pub start_ttl: u8,
    /// Maximum number of hops (default: 30)
    pub max_hops: u8,
    /// Timeout for individual probes (default: 1000ms)
    pub probe_timeout: Duration,
    /// Interval between launching probes (default: 5ms)
    pub send_interval: Duration,
    /// Overall timeout for the entire traceroute (default: 3000ms)
    pub overall_timeout: Duration,
    /// Number of probes per hop (default: 1)
    pub queries_per_hop: u8,
    /// Preferred protocol for probing (ICMP, UDP, or TCP)
    pub protocol: Option<ProbeProtocol>,
    /// Preferred socket mode (Raw, DGRAM, or Unprivileged)
    pub socket_mode: Option<SocketMode>,
    /// Target port for UDP/TCP modes (default: 443)
    pub port: u16,
    /// Enable ASN lookups (default: true)
    pub enable_asn_lookup: bool,
    /// Enable reverse DNS lookups (default: true)
    pub enable_rdns: bool,
    /// Enable verbose output
    pub verbose: bool,
    /// Public IP address (if known) to avoid repeated detection
    ///
    /// When running multiple traceroutes, you can provide the public IP
    /// to avoid repeated detection calls, improving performance.
    pub public_ip: Option<IpAddr>,
    /// Internal timing configuration
    /// Most users should not need to modify these values
    pub timing: TimingConfig,
}

impl Default for TracerouteConfig {
    fn default() -> Self {
        Self {
            target: String::new(),
            target_ip: None,
            start_ttl: 1,
            max_hops: 30,
            probe_timeout: Duration::from_millis(1000),
            send_interval: Duration::from_millis(0),
            overall_timeout: Duration::from_millis(3000),
            queries_per_hop: 1,
            protocol: None,
            socket_mode: None,
            port: 443,
            enable_asn_lookup: true,
            enable_rdns: true,
            verbose: false,
            public_ip: None,
            timing: TimingConfig::default(),
        }
    }
}

impl TracerouteConfig {
    /// Create a new TracerouteConfig builder
    ///
    /// This is the recommended way to create a TracerouteConfig instance.
    ///
    /// # Examples
    ///
    /// ```
    /// use ftr::TracerouteConfig;
    ///
    /// let config = TracerouteConfig::builder()
    ///     .target("example.com")
    ///     .build()
    ///     .unwrap();
    /// ```
    pub fn builder() -> TracerouteConfigBuilder {
        TracerouteConfigBuilder::new()
    }

    /// Validate the configuration
    ///
    /// Checks that all configuration parameters are within valid ranges
    /// and that required fields are present.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Target is empty and no target_ip is provided
    /// - start_ttl is less than 1
    /// - max_hops is less than start_ttl
    /// - probe_timeout is 0
    /// - queries_per_hop is less than 1
    pub fn validate(&self) -> Result<(), String> {
        if self.target.is_empty() && self.target_ip.is_none() {
            return Err("Target must be specified".to_string());
        }
        if self.start_ttl < 1 {
            return Err("start_ttl must be at least 1".to_string());
        }
        if self.max_hops < self.start_ttl {
            return Err("max_hops must be greater than or equal to start_ttl".to_string());
        }
        if self.probe_timeout.as_millis() == 0 {
            return Err("probe_timeout must be greater than 0".to_string());
        }
        if self.queries_per_hop < 1 {
            return Err("queries_per_hop must be at least 1".to_string());
        }
        Ok(())
    }
}

/// Builder for TracerouteConfig
///
/// Provides a fluent API for constructing TracerouteConfig instances
/// with compile-time validation and sensible defaults.
///
/// # Examples
///
/// ```
/// use ftr::{TracerouteConfigBuilder, ProbeProtocol};
/// use std::time::Duration;
///
/// let config = TracerouteConfigBuilder::new()
///     .target("8.8.8.8")
///     .protocol(ProbeProtocol::Icmp)
///     .max_hops(15)
///     .queries(3)
///     .probe_timeout(Duration::from_secs(2))
///     .build()
///     .unwrap();
/// ```
pub struct TracerouteConfigBuilder {
    config: TracerouteConfig,
}

impl TracerouteConfigBuilder {
    /// Create a new builder with default values
    ///
    /// Default values:
    /// - start_ttl: 1
    /// - max_hops: 30
    /// - probe_timeout: 1000ms
    /// - send_interval: 5ms
    /// - overall_timeout: 3000ms
    /// - queries_per_hop: 1
    /// - port: 443
    /// - enable_asn_lookup: true
    /// - enable_rdns: true
    /// - verbose: false
    pub fn new() -> Self {
        Self {
            config: TracerouteConfig::default(),
        }
    }

    /// Set the target hostname or IP address
    ///
    /// This is the only required field for a valid configuration.
    pub fn target(mut self, target: impl Into<String>) -> Self {
        self.config.target = target.into();
        self
    }

    /// Set the resolved target IP address
    ///
    /// If you've already resolved the target hostname to an IP, you can
    /// provide it here to skip DNS resolution.
    pub fn target_ip(mut self, ip: IpAddr) -> Self {
        self.config.target_ip = Some(ip);
        self
    }

    /// Set the starting TTL value
    ///
    /// The Time-To-Live value for the first probe. Default is 1.
    pub fn start_ttl(mut self, ttl: u8) -> Self {
        self.config.start_ttl = ttl;
        self
    }

    /// Set the maximum number of hops
    ///
    /// The maximum TTL value to probe. Default is 30.
    pub fn max_hops(mut self, hops: u8) -> Self {
        self.config.max_hops = hops;
        self
    }

    /// Set the probe timeout
    ///
    /// How long to wait for a response to each probe. Default is 1 second.
    pub fn probe_timeout(mut self, timeout: Duration) -> Self {
        self.config.probe_timeout = timeout;
        self
    }

    /// Set the send interval
    ///
    /// Minimum time between sending probes. Default is 5ms.
    /// Lower values enable faster parallel probing.
    pub fn send_interval(mut self, interval: Duration) -> Self {
        self.config.send_interval = interval;
        self
    }

    /// Set the overall timeout
    ///
    /// Maximum time for the entire traceroute operation. Default is 3 seconds.
    pub fn overall_timeout(mut self, timeout: Duration) -> Self {
        self.config.overall_timeout = timeout;
        self
    }

    /// Set the number of queries per hop
    ///
    /// Number of probes to send for each TTL value. Default is 1.
    /// Higher values provide more reliable RTT measurements.
    pub fn queries_per_hop(mut self, queries: u8) -> Self {
        self.config.queries_per_hop = queries;
        self
    }

    /// Set the preferred protocol
    ///
    /// Choose between ICMP, UDP, or TCP probes. The actual protocol
    /// used may differ based on system capabilities and permissions.
    pub fn protocol(mut self, protocol: ProbeProtocol) -> Self {
        self.config.protocol = Some(protocol);
        self
    }

    /// Set the preferred socket mode
    ///
    /// Choose between Raw (requires root), DGRAM (ICMP only),
    /// or Unprivileged (UDP only, no root required).
    pub fn socket_mode(mut self, mode: SocketMode) -> Self {
        self.config.socket_mode = Some(mode);
        self
    }

    /// Set the target port for UDP/TCP modes
    ///
    /// The destination port for UDP or TCP probes. Default is 443.
    /// Common values: 53 (DNS), 80 (HTTP), 443 (HTTPS).
    pub fn port(mut self, port: u16) -> Self {
        self.config.port = port;
        self
    }

    /// Enable or disable ASN lookups
    ///
    /// When enabled, queries IPtoASN.com for AS information. Default is true.
    pub fn enable_asn_lookup(mut self, enable: bool) -> Self {
        self.config.enable_asn_lookup = enable;
        self
    }

    /// Enable or disable reverse DNS lookups
    ///
    /// When enabled, performs PTR lookups for hop IP addresses. Default is true.
    pub fn enable_rdns(mut self, enable: bool) -> Self {
        self.config.enable_rdns = enable;
        self
    }

    /// Enable or disable verbose output
    ///
    /// When enabled, provides detailed socket and probe information. Default is false.
    pub fn verbose(mut self, verbose: bool) -> Self {
        self.config.verbose = verbose;
        self
    }

    /// Set the public IP address (if known)
    ///
    /// Provide a known public IP to skip detection. Useful when running
    /// multiple traceroutes to improve performance.
    pub fn public_ip(mut self, ip: IpAddr) -> Self {
        self.config.public_ip = Some(ip);
        self
    }

    /// Set custom timing configuration
    ///
    /// Advanced: Configure internal timing parameters. Most users should not need
    /// to modify these values.
    pub fn timing(mut self, timing: TimingConfig) -> Self {
        self.config.timing = timing;
        self
    }

    /// Build the configuration
    ///
    /// Validates all parameters and returns the final configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if validation fails (see [`TracerouteConfig::validate`]).
    pub fn build(self) -> Result<TracerouteConfig, String> {
        self.config.validate()?;
        Ok(self.config)
    }

    // Convenience methods

    /// Set the number of queries (alias for queries_per_hop)
    ///
    /// This is a convenience alias for [`queries_per_hop`](Self::queries_per_hop).
    pub fn queries(self, queries: u8) -> Self {
        self.queries_per_hop(queries)
    }

    /// Set parallel probes (adjusts send_interval)
    ///
    /// This is a convenience method that sets the send interval based on
    /// the desired number of parallel probes. Higher values mean shorter
    /// intervals and faster probing.
    ///
    /// # Arguments
    ///
    /// * `parallel` - Approximate number of probes to send in parallel (1-100)
    pub fn parallel_probes(mut self, parallel: u8) -> Self {
        // Calculate send interval based on parallel probes
        // More parallel = shorter interval
        let interval_ms = match parallel {
            0..=1 => 50,   // Sequential
            2..=10 => 20,  // Low parallelism
            11..=30 => 10, // Medium parallelism
            31..=50 => 5,  // High parallelism (default)
            _ => 2,        // Very high parallelism
        };
        self.config.send_interval = Duration::from_millis(interval_ms);
        self
    }
}

impl Default for TracerouteConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_default_config() {
        let config = TracerouteConfig::default();
        assert_eq!(config.start_ttl, 1);
        assert_eq!(config.max_hops, 30);
        assert_eq!(config.probe_timeout.as_millis(), 1000);
        assert_eq!(config.queries_per_hop, 1);
        assert!(config.enable_asn_lookup);
        assert!(config.enable_rdns);
    }

    #[test]
    fn test_config_builder() {
        let config = TracerouteConfig::builder()
            .target("google.com")
            .max_hops(20)
            .probe_timeout(Duration::from_millis(500))
            .queries_per_hop(3)
            .build()
            .unwrap();

        assert_eq!(config.target, "google.com");
        assert_eq!(config.max_hops, 20);
        assert_eq!(config.probe_timeout.as_millis(), 500);
        assert_eq!(config.queries_per_hop, 3);
    }

    #[test]
    fn test_config_validation() {
        // Empty target
        let result = TracerouteConfig::builder().build();
        assert!(result.is_err());

        // Invalid start_ttl
        let result = TracerouteConfig::builder()
            .target("example.com")
            .start_ttl(0)
            .build();
        assert!(result.is_err());

        // max_hops < start_ttl
        let result = TracerouteConfig::builder()
            .target("example.com")
            .start_ttl(10)
            .max_hops(5)
            .build();
        assert!(result.is_err());

        // Zero probe timeout
        let result = TracerouteConfig::builder()
            .target("example.com")
            .probe_timeout(Duration::from_millis(0))
            .build();
        assert!(result.is_err());

        // Zero queries per hop
        let result = TracerouteConfig::builder()
            .target("example.com")
            .queries_per_hop(0)
            .build();
        assert!(result.is_err());
    }

    #[test]
    fn test_config_with_ip() {
        let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let config = TracerouteConfig::builder().target_ip(ip).build().unwrap();

        assert_eq!(config.target_ip, Some(ip));
    }
}
