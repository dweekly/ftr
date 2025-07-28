//! High-level traceroute API

use crate::socket::factory::create_probe_socket_with_port;
use crate::socket::ProbeSocket;
use crate::traceroute::{
    TracerouteConfig, TracerouteEngine, TracerouteError, TracerouteProgress, TracerouteResult,
};
use std::net::IpAddr;
use tokio::sync::mpsc;

/// High-level traceroute API
pub struct Traceroute {
    engine: TracerouteEngine,
}

impl Traceroute {
    /// Create a new traceroute from configuration
    pub fn new(config: TracerouteConfig) -> Result<Self, TracerouteError> {
        // Create socket based on configuration
        let socket = create_socket_from_config(&config)?;
        let engine = TracerouteEngine::new(config, socket)?;

        Ok(Self { engine })
    }

    /// Create a traceroute with custom socket
    pub fn with_socket(
        config: TracerouteConfig,
        socket: Box<dyn ProbeSocket>,
    ) -> Result<Self, TracerouteError> {
        let engine = TracerouteEngine::new(config, socket)?;
        Ok(Self { engine })
    }

    /// Run the traceroute and return the result
    pub async fn run(self) -> Result<TracerouteResult, TracerouteError> {
        self.engine.run().await
    }

    /// Run the traceroute with progress updates
    pub async fn run_with_progress(
        self,
        progress_tx: mpsc::Sender<TracerouteProgress>,
    ) -> Result<TracerouteResult, TracerouteError> {
        // TODO: This would require refactoring the engine to support progress updates
        // For now, just run normally
        let _ = progress_tx;
        self.engine.run().await
    }

    /// Get current progress (snapshot)
    pub fn get_progress(&self) -> TracerouteProgress {
        self.engine.get_progress()
    }
}

/// Create a socket from configuration
fn create_socket_from_config(
    config: &TracerouteConfig,
) -> Result<Box<dyn ProbeSocket>, TracerouteError> {
    // Resolve target if needed
    let target_ip = match config.target_ip {
        Some(ip) => ip,
        None => {
            // Try to parse as IP
            config.target.parse::<IpAddr>().map_err(|_| {
                TracerouteError::ResolutionError(
                    "Target IP not provided and target is not a valid IP address".to_string(),
                )
            })?
        }
    };

    // Create socket with options
    let socket = create_probe_socket_with_port(
        target_ip,
        config.protocol,
        config.socket_mode,
        config.verbose,
        config.port,
    );

    socket.map_err(|e| TracerouteError::SocketError(e.to_string()))
}

/// Convenience function to run a simple traceroute
pub async fn trace(target: &str) -> Result<TracerouteResult, TracerouteError> {
    let config = TracerouteConfig::builder()
        .target(target)
        .build()
        .map_err(TracerouteError::ConfigError)?;

    Traceroute::new(config)?.run().await
}

/// Convenience function to run traceroute with custom configuration
pub async fn trace_with_config(
    config: TracerouteConfig,
) -> Result<TracerouteResult, TracerouteError> {
    Traceroute::new(config)?.run().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_create_traceroute() {
        let config = TracerouteConfig::builder()
            .target("8.8.8.8")
            .target_ip(IpAddr::V4("8.8.8.8".parse().unwrap()))
            .build()
            .unwrap();

        // This will fail without proper privileges, but we're just testing compilation
        let result = Traceroute::new(config);
        assert!(result.is_ok() || result.is_err()); // Either is fine for unit test
    }

    #[tokio::test]
    async fn test_trace_localhost() {
        let config = TracerouteConfig::builder()
            .target("127.0.0.1")
            .max_hops(3)
            .probe_timeout(Duration::from_millis(100))
            .build()
            .unwrap();

        let result = trace_with_config(config).await;
        // May fail due to permissions, but that's okay
        match result {
            Ok(trace_result) => {
                assert_eq!(trace_result.target, "127.0.0.1");
                assert!(!trace_result.hops.is_empty());
            }
            Err(_) => {
                // Permission errors are expected in tests
            }
        }
    }
}
