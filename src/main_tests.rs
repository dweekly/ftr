//! Tests for main.rs functionality

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use crate::*;
    use clap::Parser;
    use ftr::{ProbeProtocol, SocketMode};
    use std::net::IpAddr;

    #[test]
    fn test_get_version() {
        let version = get_version();
        assert!(!version.is_empty());

        #[cfg(debug_assertions)]
        assert!(version.ends_with("-UNRELEASED"));

        #[cfg(not(debug_assertions))]
        assert!(!version.contains("UNRELEASED"));
    }

    #[tokio::test]
    async fn test_resolve_target_ip_address() {
        // Test with IPv4 address
        let result = resolve_target("8.8.8.8").await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "8.8.8.8".parse::<IpAddr>().unwrap());

        // Test with IPv6 address
        let result = resolve_target("::1").await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "::1".parse::<IpAddr>().unwrap());
    }

    #[tokio::test]
    async fn test_resolve_target_hostname() {
        // Test with localhost
        let result = resolve_target("localhost").await;
        assert!(result.is_ok());
        let ip = result.unwrap();
        assert!(ip.is_loopback());
    }

    #[tokio::test]
    async fn test_resolve_target_invalid() {
        let result = resolve_target("this.domain.definitely.does.not.exist.invalid").await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Error resolving host"));
    }

    #[test]
    fn test_display_json_results() {
        use ftr::{ClassifiedHopInfo, IspInfo, SegmentType, TracerouteResult};
        use std::net::Ipv4Addr;
        use std::time::Duration;

        let result = TracerouteResult {
            target: "example.com".to_string(),
            target_ip: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            hops: vec![ClassifiedHopInfo {
                ttl: 1,
                segment: SegmentType::Lan,
                hostname: Some("router.local".to_string()),
                addr: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
                asn_info: None,
                rtt: Some(Duration::from_millis(5)),
            }],
            isp_info: Some(IspInfo {
                public_ip: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
                asn: 12345,
                name: "Test ISP".to_string(),
                hostname: None,
            }),
            protocol_used: ftr::ProbeProtocol::Icmp,
            socket_mode_used: ftr::SocketMode::Raw,
            destination_reached: true,
            total_duration: Duration::from_secs(1),
        };

        let json_result = display_json_results(result);
        assert!(json_result.is_ok());

        // We can't easily capture stdout in unit tests, but we can verify it doesn't panic
    }

    #[test]
    fn test_display_text_results_with_enrichment() {
        use ftr::{AsnInfo, ClassifiedHopInfo, SegmentType, TracerouteResult};
        use std::net::Ipv4Addr;
        use std::time::Duration;

        let result = TracerouteResult {
            target: "example.com".to_string(),
            target_ip: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            hops: vec![ClassifiedHopInfo {
                ttl: 1,
                segment: SegmentType::Lan,
                hostname: Some("router.local".to_string()),
                addr: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
                asn_info: Some(AsnInfo {
                    asn: 12345,
                    prefix: "192.168.0.0/16".to_string(),
                    country_code: "US".to_string(),
                    registry: "ARIN".to_string(),
                    name: "LOCAL-NET".to_string(),
                }),
                rtt: Some(Duration::from_millis(5)),
            }],
            isp_info: None,
            protocol_used: ftr::ProbeProtocol::Icmp,
            socket_mode_used: ftr::SocketMode::Raw,
            destination_reached: true,
            total_duration: Duration::from_secs(1),
        };

        // Test doesn't panic
        display_text_results(result, false, false);
    }

    #[test]
    fn test_args_parsing() {
        // Test default args
        let args = Args::parse_from(["ftr", "google.com"]);
        assert_eq!(args.host, "google.com");
        assert_eq!(args.start_ttl, 1);
        assert_eq!(args.max_hops, 30);
        assert_eq!(args.probe_timeout_ms, 1000);
        assert_eq!(args.queries, 1);
        assert!(!args.json);
        assert!(!args.no_enrich);
        assert!(!args.no_rdns);

        // Test custom args
        let args = Args::parse_from([
            "ftr",
            "example.com",
            "--start-ttl",
            "5",
            "--max-hops",
            "20",
            "--queries",
            "3",
            "--json",
            "--no-enrich",
            "--port",
            "80",
        ]);
        assert_eq!(args.host, "example.com");
        assert_eq!(args.start_ttl, 5);
        assert_eq!(args.max_hops, 20);
        assert_eq!(args.queries, 3);
        assert!(args.json);
        assert!(args.no_enrich);
        assert_eq!(args.port, 80);

        // Test protocol and socket mode
        let args = Args::parse_from([
            "ftr",
            "test.com",
            "--protocol",
            "udp",
            "--socket-mode",
            "raw",
        ]);
        assert!(matches!(args.protocol, Some(ProtocolArg::Udp)));
        assert!(matches!(args.socket_mode, Some(SocketModeArg::Raw)));
    }

    #[test]
    fn test_json_output_structure() {
        use ftr::{AsnInfo, ClassifiedHopInfo, SegmentType, TracerouteResult};
        use std::net::Ipv4Addr;
        use std::time::Duration;

        let result = TracerouteResult {
            target: "example.com".to_string(),
            target_ip: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            hops: vec![
                ClassifiedHopInfo {
                    ttl: 1,
                    segment: SegmentType::Lan,
                    hostname: Some("router.local".to_string()),
                    addr: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
                    asn_info: None,
                    rtt: Some(Duration::from_millis(5)),
                },
                ClassifiedHopInfo {
                    ttl: 2,
                    segment: SegmentType::Isp,
                    hostname: None,
                    addr: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
                    asn_info: Some(AsnInfo {
                        asn: 12345,
                        prefix: "10.0.0.0/8".to_string(),
                        country_code: "US".to_string(),
                        registry: "ARIN".to_string(),
                        name: "ISP".to_string(),
                    }),
                    rtt: Some(Duration::from_millis(15)),
                },
            ],
            isp_info: None,
            protocol_used: ftr::ProbeProtocol::Icmp,
            socket_mode_used: ftr::SocketMode::Raw,
            destination_reached: true,
            total_duration: Duration::from_secs(1),
        };

        // Test JSON serialization doesn't panic
        let json_result = display_json_results(result);
        assert!(json_result.is_ok());
    }

    #[test]
    fn test_json_hop_structure() {
        let hop = JsonHop {
            ttl: 5,
            segment: Some("Isp".to_string()),
            address: Some("8.8.8.8".to_string()),
            hostname: Some("dns.google".to_string()),
            asn_info: Some(ftr::AsnInfo {
                asn: 15169,
                prefix: "8.8.8.0/24".to_string(),
                country_code: "US".to_string(),
                registry: "ARIN".to_string(),
                name: "GOOGLE".to_string(),
            }),
            rtt_ms: Some(25.5),
        };

        // Test serialization
        let json = serde_json::to_string(&hop);
        assert!(json.is_ok());

        // Test with None values
        let empty_hop = JsonHop {
            ttl: 10,
            segment: None,
            address: None,
            hostname: None,
            asn_info: None,
            rtt_ms: None,
        };

        let json = serde_json::to_string(&empty_hop);
        assert!(json.is_ok());
    }

    #[test]
    fn test_protocol_arg_conversion() {
        // Test enum conversions
        let icmp = ProtocolArg::Icmp;
        let udp = ProtocolArg::Udp;

        let proto_icmp = match icmp {
            ProtocolArg::Icmp => ProbeProtocol::Icmp,
            ProtocolArg::Udp => ProbeProtocol::Udp,
        };
        assert_eq!(proto_icmp, ProbeProtocol::Icmp);

        let proto_udp = match udp {
            ProtocolArg::Icmp => ProbeProtocol::Icmp,
            ProtocolArg::Udp => ProbeProtocol::Udp,
        };
        assert_eq!(proto_udp, ProbeProtocol::Udp);
    }

    #[test]
    fn test_socket_mode_arg_conversion() {
        let raw = SocketModeArg::Raw;
        let dgram = SocketModeArg::Dgram;

        let mode_raw = match raw {
            SocketModeArg::Raw => SocketMode::Raw,
            SocketModeArg::Dgram => SocketMode::Dgram,
        };
        assert_eq!(mode_raw, SocketMode::Raw);

        let mode_dgram = match dgram {
            SocketModeArg::Raw => SocketMode::Raw,
            SocketModeArg::Dgram => SocketMode::Dgram,
        };
        assert_eq!(mode_dgram, SocketMode::Dgram);
    }

    #[test]
    fn test_display_text_results_without_enrichment() {
        use ftr::{ClassifiedHopInfo, SegmentType, TracerouteResult};
        use std::net::Ipv4Addr;
        use std::time::Duration;

        let result = TracerouteResult {
            target: "example.com".to_string(),
            target_ip: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            hops: vec![
                ClassifiedHopInfo {
                    ttl: 1,
                    segment: SegmentType::Unknown,
                    hostname: None,
                    addr: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
                    asn_info: None,
                    rtt: Some(Duration::from_millis(5)),
                },
                ClassifiedHopInfo {
                    ttl: 2,
                    segment: SegmentType::Unknown,
                    hostname: None,
                    addr: None, // Silent hop
                    asn_info: None,
                    rtt: None,
                },
            ],
            isp_info: None,
            protocol_used: ftr::ProbeProtocol::Icmp,
            socket_mode_used: ftr::SocketMode::Raw,
            destination_reached: false,
            total_duration: Duration::from_secs(1),
        };

        // Test doesn't panic and handles silent hops correctly
        display_text_results(result, false, false);
    }
}
