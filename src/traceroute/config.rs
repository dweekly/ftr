//! Configuration types for traceroute operations

use crate::socket::{ProbeProtocol, SocketMode};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::time::Duration;

/// Configuration for a traceroute operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracerouteConfig {
    /// Target hostname or IP address
    pub target: String,
    /// Resolved target IP address
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
    /// Preferred protocol for probing
    pub protocol: Option<ProbeProtocol>,
    /// Preferred socket mode
    pub socket_mode: Option<SocketMode>,
    /// Target port for UDP/TCP modes (default: 443)
    pub port: u16,
    /// Enable ASN lookups (default: true)
    pub enable_asn_lookup: bool,
    /// Enable reverse DNS lookups (default: true)
    pub enable_rdns: bool,
    /// Enable verbose output
    pub verbose: bool,
}

impl Default for TracerouteConfig {
    fn default() -> Self {
        Self {
            target: String::new(),
            target_ip: None,
            start_ttl: 1,
            max_hops: 30,
            probe_timeout: Duration::from_millis(1000),
            send_interval: Duration::from_millis(5),
            overall_timeout: Duration::from_millis(3000),
            queries_per_hop: 1,
            protocol: None,
            socket_mode: None,
            port: 443,
            enable_asn_lookup: true,
            enable_rdns: true,
            verbose: false,
        }
    }
}

impl TracerouteConfig {
    /// Create a new TracerouteConfig builder
    pub fn builder() -> TracerouteConfigBuilder {
        TracerouteConfigBuilder::new()
    }

    /// Validate the configuration
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
pub struct TracerouteConfigBuilder {
    config: TracerouteConfig,
}

impl TracerouteConfigBuilder {
    /// Create a new builder with default values
    pub fn new() -> Self {
        Self {
            config: TracerouteConfig::default(),
        }
    }

    /// Set the target hostname or IP address
    pub fn target(mut self, target: impl Into<String>) -> Self {
        self.config.target = target.into();
        self
    }

    /// Set the resolved target IP address
    pub fn target_ip(mut self, ip: IpAddr) -> Self {
        self.config.target_ip = Some(ip);
        self
    }

    /// Set the starting TTL value
    pub fn start_ttl(mut self, ttl: u8) -> Self {
        self.config.start_ttl = ttl;
        self
    }

    /// Set the maximum number of hops
    pub fn max_hops(mut self, hops: u8) -> Self {
        self.config.max_hops = hops;
        self
    }

    /// Set the probe timeout
    pub fn probe_timeout(mut self, timeout: Duration) -> Self {
        self.config.probe_timeout = timeout;
        self
    }

    /// Set the send interval
    pub fn send_interval(mut self, interval: Duration) -> Self {
        self.config.send_interval = interval;
        self
    }

    /// Set the overall timeout
    pub fn overall_timeout(mut self, timeout: Duration) -> Self {
        self.config.overall_timeout = timeout;
        self
    }

    /// Set the number of queries per hop
    pub fn queries_per_hop(mut self, queries: u8) -> Self {
        self.config.queries_per_hop = queries;
        self
    }

    /// Set the preferred protocol
    pub fn protocol(mut self, protocol: ProbeProtocol) -> Self {
        self.config.protocol = Some(protocol);
        self
    }

    /// Set the preferred socket mode
    pub fn socket_mode(mut self, mode: SocketMode) -> Self {
        self.config.socket_mode = Some(mode);
        self
    }

    /// Set the target port for UDP/TCP modes
    pub fn port(mut self, port: u16) -> Self {
        self.config.port = port;
        self
    }

    /// Enable or disable ASN lookups
    pub fn enable_asn_lookup(mut self, enable: bool) -> Self {
        self.config.enable_asn_lookup = enable;
        self
    }

    /// Enable or disable reverse DNS lookups
    pub fn enable_rdns(mut self, enable: bool) -> Self {
        self.config.enable_rdns = enable;
        self
    }

    /// Enable or disable verbose output
    pub fn verbose(mut self, verbose: bool) -> Self {
        self.config.verbose = verbose;
        self
    }

    /// Build the configuration
    pub fn build(self) -> Result<TracerouteConfig, String> {
        self.config.validate()?;
        Ok(self.config)
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
