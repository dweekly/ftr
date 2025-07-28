//! Comprehensive tests for the traceroute engine

#[cfg(test)]
mod tests {
    use super::super::*;
    use crate::socket::{ProbeInfo, ProbeMode, ProbeResponse, ProbeSocket, ResponseType};
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    /// Mock socket for testing
    struct MockSocket {
        responses: Arc<Mutex<Vec<ProbeResponse>>>,
        mode: ProbeMode,
        destination_reached: Arc<Mutex<bool>>,
        ttl: Arc<Mutex<u8>>,
    }

    impl MockSocket {
        fn new(mode: ProbeMode) -> Self {
            Self {
                responses: Arc::new(Mutex::new(Vec::new())),
                mode,
                destination_reached: Arc::new(Mutex::new(false)),
                ttl: Arc::new(Mutex::new(1)),
            }
        }

        fn add_response(&self, response: ProbeResponse) {
            self.responses.lock().unwrap().push(response);
        }

        fn set_destination_reached(&self, reached: bool) {
            *self.destination_reached.lock().unwrap() = reached;
        }
    }

    impl ProbeSocket for MockSocket {
        fn send_probe(&self, _target: IpAddr, probe_info: ProbeInfo) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            // Simulate probe sent
            Ok(())
        }

        fn recv_response(&self, _timeout: Duration) -> Result<Option<ProbeResponse>, Box<dyn std::error::Error + Send + Sync>> {
            let mut responses = self.responses.lock().unwrap();
            if let Some(response) = responses.pop() {
                Ok(Some(response))
            } else {
                Ok(None)
            }
        }

        fn set_ttl(&mut self, ttl: u8) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            *self.ttl.lock().unwrap() = ttl;
            Ok(())
        }

        fn mode(&self) -> ProbeMode {
            self.mode.clone()
        }

        fn destination_reached(&self) -> bool {
            *self.destination_reached.lock().unwrap()
        }
    }

    fn create_test_config() -> TracerouteConfig {
        TracerouteConfigBuilder::new()
            .target("example.com")
            .target_ip(Some(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))))
            .start_ttl(1)
            .max_hops(5)
            .probe_timeout(Duration::from_millis(100))
            .overall_timeout(Duration::from_secs(1))
            .queries_per_hop(1)
            .enable_asn_lookup(false)
            .enable_rdns(false)
            .build()
            .unwrap()
    }

    #[tokio::test]
    async fn test_engine_basic_traceroute() {
        let config = create_test_config();
        let mock_socket = Box::new(MockSocket::new(ProbeMode {
            protocol: crate::ProbeProtocol::Icmp,
            socket_mode: crate::SocketMode::Raw,
            ip_version: crate::IpVersion::V4,
        }));

        // Add mock responses
        let socket_ref = mock_socket.as_ref() as *const MockSocket;
        unsafe {
            let socket = &*socket_ref;
            socket.add_response(ProbeResponse {
                from_addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                response_type: ResponseType::TimeExceeded,
                probe_info: ProbeInfo {
                    ttl: 1,
                    identifier: 1,
                    sequence: 1,
                    sent_at: Instant::now(),
                },
                rtt: Duration::from_millis(5),
            });
        }

        let engine = TracerouteEngine::new(config, mock_socket).unwrap();
        let result = engine.run().await;
        
        assert!(result.is_ok());
        let result = result.unwrap();
        assert!(!result.hops.is_empty());
    }

    #[tokio::test]
    async fn test_engine_destination_reached() {
        let config = create_test_config();
        let target_ip = Ipv4Addr::new(93, 184, 216, 34);
        
        let mock_socket = Box::new(MockSocket::new(ProbeMode {
            protocol: crate::ProbeProtocol::Icmp,
            socket_mode: crate::SocketMode::Raw,
            ip_version: crate::IpVersion::V4,
        }));

        // Add responses including destination
        let socket_ref = mock_socket.as_ref() as *const MockSocket;
        unsafe {
            let socket = &*socket_ref;
            
            // TTL 1 response
            socket.add_response(ProbeResponse {
                from_addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                response_type: ResponseType::TimeExceeded,
                probe_info: ProbeInfo {
                    ttl: 1,
                    identifier: 1,
                    sequence: 1,
                    sent_at: Instant::now(),
                },
                rtt: Duration::from_millis(5),
            });
            
            // TTL 2 - destination response
            socket.add_response(ProbeResponse {
                from_addr: IpAddr::V4(target_ip),
                response_type: ResponseType::EchoReply,
                probe_info: ProbeInfo {
                    ttl: 2,
                    identifier: 1,
                    sequence: 2,
                    sent_at: Instant::now(),
                },
                rtt: Duration::from_millis(10),
            });
            
            socket.set_destination_reached(true);
        }

        let engine = TracerouteEngine::new(config, mock_socket).unwrap();
        let result = engine.run().await;
        
        assert!(result.is_ok());
        let result = result.unwrap();
        assert!(result.destination_reached);
        assert_eq!(result.target_ip, IpAddr::V4(target_ip));
    }

    #[tokio::test]
    async fn test_engine_timeout_handling() {
        let mut config = create_test_config();
        config.overall_timeout = Duration::from_millis(50);
        
        let mock_socket = Box::new(MockSocket::new(ProbeMode {
            protocol: crate::ProbeProtocol::Icmp,
            socket_mode: crate::SocketMode::Raw,
            ip_version: crate::IpVersion::V4,
        }));

        // Don't add any responses to simulate timeout
        let engine = TracerouteEngine::new(config, mock_socket).unwrap();
        let result = engine.run().await;
        
        assert!(result.is_ok());
        let result = result.unwrap();
        // Should have some hops even if they're empty (timeouts)
        assert!(!result.hops.is_empty());
        assert!(!result.destination_reached);
    }

    #[tokio::test]
    async fn test_engine_silent_hops() {
        let config = create_test_config();
        let mock_socket = Box::new(MockSocket::new(ProbeMode {
            protocol: crate::ProbeProtocol::Icmp,
            socket_mode: crate::SocketMode::Raw,
            ip_version: crate::IpVersion::V4,
        }));

        // Add responses with gaps (silent hops)
        let socket_ref = mock_socket.as_ref() as *const MockSocket;
        unsafe {
            let socket = &*socket_ref;
            
            // TTL 1 response
            socket.add_response(ProbeResponse {
                from_addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                response_type: ResponseType::TimeExceeded,
                probe_info: ProbeInfo {
                    ttl: 1,
                    identifier: 1,
                    sequence: 1,
                    sent_at: Instant::now(),
                },
                rtt: Duration::from_millis(5),
            });
            
            // Skip TTL 2 (silent hop)
            
            // TTL 3 response
            socket.add_response(ProbeResponse {
                from_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                response_type: ResponseType::TimeExceeded,
                probe_info: ProbeInfo {
                    ttl: 3,
                    identifier: 1,
                    sequence: 3,
                    sent_at: Instant::now(),
                },
                rtt: Duration::from_millis(15),
            });
        }

        let engine = TracerouteEngine::new(config, mock_socket).unwrap();
        let result = engine.run().await;
        
        assert!(result.is_ok());
        let result = result.unwrap();
        
        // Should have at least 3 hops
        assert!(result.hops.len() >= 3);
        
        // Check for silent hop at TTL 2
        let ttl2_hop = result.hops.iter().find(|h| h.ttl == 2);
        assert!(ttl2_hop.is_some());
        assert!(ttl2_hop.unwrap().addr.is_none());
    }

    #[tokio::test]
    async fn test_engine_progress_tracking() {
        let config = create_test_config();
        let mock_socket = Box::new(MockSocket::new(ProbeMode {
            protocol: crate::ProbeProtocol::Icmp,
            socket_mode: crate::SocketMode::Raw,
            ip_version: crate::IpVersion::V4,
        }));

        let engine = TracerouteEngine::new(config, mock_socket).unwrap();
        
        // Get initial progress
        let progress = engine.get_progress();
        assert_eq!(progress.current_ttl, 1);
        assert_eq!(progress.max_ttl, 5);
        assert_eq!(progress.hops_discovered, 0);
        assert!(!progress.destination_reached);
    }

    #[test]
    fn test_engine_invalid_config() {
        let config = TracerouteConfig {
            target: String::new(), // Invalid empty target
            target_ip: None,
            start_ttl: 1,
            max_hops: 30,
            probe_timeout: Duration::from_millis(1000),
            send_interval: Duration::from_millis(5),
            overall_timeout: Duration::from_secs(3),
            queries_per_hop: 1,
            enable_asn_lookup: false,
            enable_rdns: false,
            verbose: false,
            port: 443,
            protocol: None,
            socket_mode: None,
        };

        let mock_socket = Box::new(MockSocket::new(ProbeMode {
            protocol: crate::ProbeProtocol::Icmp,
            socket_mode: crate::SocketMode::Raw,
            ip_version: crate::IpVersion::V4,
        }));

        let result = TracerouteEngine::new(config, mock_socket);
        assert!(result.is_err());
    }
}