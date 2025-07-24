//! Integration tests for ftr

#[cfg(test)]
mod socket_tests {
    use crate::socket::{ProbeInfo, ProbeResponse, ResponseType};
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::{Duration, Instant};

    #[test]
    fn test_probe_info_creation() {
        let now = Instant::now();
        let probe_info = ProbeInfo {
            ttl: 5,
            sequence: 1234,
            identifier: 5678,
            sent_at: now,
        };

        assert_eq!(probe_info.ttl, 5);
        assert_eq!(probe_info.sequence, 1234);
        assert_eq!(probe_info.identifier, 5678);
        assert_eq!(probe_info.sent_at, now);
    }

    #[test]
    fn test_response_type_variants() {
        // Test TimeExceeded
        let te = ResponseType::TimeExceeded;
        assert_eq!(te, ResponseType::TimeExceeded);

        // Test DestinationUnreachable with code
        let du = ResponseType::DestinationUnreachable(3); // Port unreachable
        if let ResponseType::DestinationUnreachable(code) = du {
            assert_eq!(code, 3);
        } else {
            panic!("Wrong variant");
        }

        // Test EchoReply
        let er = ResponseType::EchoReply;
        assert_eq!(er, ResponseType::EchoReply);

        // Test other variants
        let tcp_syn = ResponseType::TcpSynAck;
        assert_eq!(tcp_syn, ResponseType::TcpSynAck);

        let tcp_rst = ResponseType::TcpRst;
        assert_eq!(tcp_rst, ResponseType::TcpRst);

        let udp_unreach = ResponseType::UdpPortUnreachable;
        assert_eq!(udp_unreach, ResponseType::UdpPortUnreachable);
    }

    #[test]
    fn test_probe_response() {
        let probe_info = ProbeInfo {
            ttl: 10,
            identifier: 1000,
            sequence: 1,
            sent_at: Instant::now(),
        };

        let response = ProbeResponse {
            from_addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            response_type: ResponseType::TimeExceeded,
            probe_info: probe_info.clone(),
            rtt: Duration::from_millis(15),
        };

        assert_eq!(
            response.from_addr,
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))
        );
        assert_eq!(response.response_type, ResponseType::TimeExceeded);
        assert_eq!(response.rtt, Duration::from_millis(15));
        assert_eq!(response.probe_info.ttl, 10);
    }
}
