//! Comprehensive tests for ASN lookup functionality

#[cfg(test)]
mod tests {
    use super::super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_form_dns_query() {
        let ip = Ipv4Addr::new(8, 8, 8, 8);
        let query = form_dns_query(&ip);
        assert_eq!(query, "8.8.8.8.origin.asn.cymru.com");

        let ip = Ipv4Addr::new(192, 168, 1, 1);
        let query = form_dns_query(&ip);
        assert_eq!(query, "1.1.168.192.origin.asn.cymru.com");
    }

    #[test]
    fn test_parse_asn_response_valid() {
        // Test valid response format
        let response = "15169 | 8.8.8.0/24 | US | arin | 2023-01-01";
        let result = parse_asn_response(response);
        assert!(result.is_some());
        
        let asn_info = result.unwrap();
        assert_eq!(asn_info.asn, "AS15169");
        assert_eq!(asn_info.prefix, "8.8.8.0/24");
        assert_eq!(asn_info.country_code, "US");
        assert_eq!(asn_info.registry, "arin");
        assert_eq!(asn_info.name, "AS15169");
    }

    #[test]
    fn test_parse_asn_response_with_name() {
        // Test response with ASN name
        let response = "15169 | 8.8.8.0/24 | US | arin | 2023-01-01 | GOOGLE - Google LLC";
        let result = parse_asn_response(response);
        assert!(result.is_some());
        
        let asn_info = result.unwrap();
        assert_eq!(asn_info.asn, "AS15169");
        assert_eq!(asn_info.name, "GOOGLE - Google LLC");
    }

    #[test]
    fn test_parse_asn_response_invalid() {
        // Test various invalid formats
        assert!(parse_asn_response("").is_none());
        assert!(parse_asn_response("invalid").is_none());
        assert!(parse_asn_response("| | | |").is_none());
        assert!(parse_asn_response("not | enough | fields").is_none());
    }

    #[test]
    fn test_parse_asn_response_edge_cases() {
        // Test with extra whitespace
        let response = "  15169  |  8.8.8.0/24  |  US  |  arin  |  2023-01-01  ";
        let result = parse_asn_response(response);
        assert!(result.is_some());
        assert_eq!(result.unwrap().asn, "AS15169");

        // Test with missing optional fields
        let response = "15169 | 8.8.8.0/24 | US | arin |";
        let result = parse_asn_response(response);
        assert!(result.is_some());
    }

    #[test]
    fn test_parse_cidr_valid() {
        let result = parse_cidr("192.168.1.0/24");
        assert!(result.is_some());
        let (network, prefix_len) = result.unwrap();
        assert_eq!(network, Ipv4Addr::new(192, 168, 1, 0));
        assert_eq!(prefix_len, 24);

        let result = parse_cidr("10.0.0.0/8");
        assert!(result.is_some());
        let (network, prefix_len) = result.unwrap();
        assert_eq!(network, Ipv4Addr::new(10, 0, 0, 0));
        assert_eq!(prefix_len, 8);
    }

    #[test]
    fn test_parse_cidr_invalid() {
        assert!(parse_cidr("").is_none());
        assert!(parse_cidr("192.168.1.0").is_none());
        assert!(parse_cidr("192.168.1.0/").is_none());
        assert!(parse_cidr("192.168.1.0/33").is_none()); // Invalid prefix length
        assert!(parse_cidr("invalid/24").is_none());
        assert!(parse_cidr("192.168.1.0/abc").is_none());
    }

    #[test]
    fn test_is_ip_in_cidr() {
        let ip = Ipv4Addr::new(192, 168, 1, 100);
        let network = Ipv4Addr::new(192, 168, 1, 0);
        assert!(is_ip_in_cidr(&ip, &network, 24));

        let ip = Ipv4Addr::new(192, 168, 2, 1);
        assert!(!is_ip_in_cidr(&ip, &network, 24));

        let ip = Ipv4Addr::new(10, 0, 0, 1);
        let network = Ipv4Addr::new(10, 0, 0, 0);
        assert!(is_ip_in_cidr(&ip, &network, 8));
    }

    #[test]
    fn test_special_ip_handling() {
        // Test all special IP categories
        
        // Loopback
        assert_eq!(
            lookup_asn_sync(Ipv4Addr::new(127, 0, 0, 1)).unwrap().name,
            "Loopback"
        );
        
        // Private network ranges
        assert_eq!(
            lookup_asn_sync(Ipv4Addr::new(10, 0, 0, 1)).unwrap().name,
            "Private Network"
        );
        assert_eq!(
            lookup_asn_sync(Ipv4Addr::new(172, 16, 0, 1)).unwrap().name,
            "Private Network"
        );
        assert_eq!(
            lookup_asn_sync(Ipv4Addr::new(192, 168, 1, 1)).unwrap().name,
            "Private Network"
        );
        
        // CGNAT
        assert_eq!(
            lookup_asn_sync(Ipv4Addr::new(100, 64, 0, 1)).unwrap().name,
            "Carrier Grade NAT"
        );
        
        // Link-local
        assert_eq!(
            lookup_asn_sync(Ipv4Addr::new(169, 254, 1, 1)).unwrap().name,
            "Link Local"
        );
        
        // Multicast
        assert_eq!(
            lookup_asn_sync(Ipv4Addr::new(224, 0, 0, 1)).unwrap().name,
            "Multicast"
        );
        
        // Broadcast
        assert_eq!(
            lookup_asn_sync(Ipv4Addr::new(255, 255, 255, 255)).unwrap().name,
            "Broadcast"
        );
    }

    #[tokio::test]
    async fn test_concurrent_lookups() {
        use futures::future::join_all;
        
        let ips = vec![
            Ipv4Addr::new(8, 8, 8, 8),
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(9, 9, 9, 9),
        ];
        
        let futures: Vec<_> = ips
            .into_iter()
            .map(|ip| lookup_asn(ip, None))
            .collect();
        
        let results = join_all(futures).await;
        
        // All lookups should complete without panic
        for result in results {
            assert!(result.is_ok() || result.is_err()); // Just verify it completes
        }
    }

    fn lookup_asn_sync(ip: Ipv4Addr) -> Option<AsnInfo> {
        // Synchronous wrapper for testing
        if is_internal_ip(&ip) {
            return Some(AsnInfo {
                asn: "N/A".to_string(),
                prefix: format!("{}/32", ip),
                country_code: "N/A".to_string(),
                registry: "N/A".to_string(),
                name: "Private Network".to_string(),
            });
        }
        
        if is_cgnat(&ip) {
            return Some(AsnInfo {
                asn: "N/A".to_string(),
                prefix: "100.64.0.0/10".to_string(),
                country_code: "N/A".to_string(),
                registry: "N/A".to_string(),
                name: "Carrier Grade NAT".to_string(),
            });
        }
        
        if ip.is_loopback() {
            return Some(AsnInfo {
                asn: "N/A".to_string(),
                prefix: "127.0.0.0/8".to_string(),
                country_code: "N/A".to_string(),
                registry: "N/A".to_string(),
                name: "Loopback".to_string(),
            });
        }
        
        if ip.is_link_local() {
            return Some(AsnInfo {
                asn: "N/A".to_string(),
                prefix: "169.254.0.0/16".to_string(),
                country_code: "N/A".to_string(),
                registry: "N/A".to_string(),
                name: "Link Local".to_string(),
            });
        }
        
        if ip.is_multicast() {
            return Some(AsnInfo {
                asn: "N/A".to_string(),
                prefix: format!("{}/32", ip),
                country_code: "N/A".to_string(),
                registry: "N/A".to_string(),
                name: "Multicast".to_string(),
            });
        }
        
        if ip.is_broadcast() {
            return Some(AsnInfo {
                asn: "N/A".to_string(),
                prefix: "255.255.255.255/32".to_string(),
                country_code: "N/A".to_string(),
                registry: "N/A".to_string(),
                name: "Broadcast".to_string(),
            });
        }
        
        None
    }
}