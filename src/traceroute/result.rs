//! Result types for traceroute operations

use crate::socket::{ProbeProtocol, SocketMode};
use crate::traceroute::types::{ClassifiedHopInfo, IspInfo};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Result of a traceroute operation
///
/// Contains all the information gathered during a traceroute, including
/// discovered hops, ISP information, and metadata about the operation.
///
/// # Examples
///
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let result = ftr::trace("google.com").await?;
///
/// println!("Reached destination: {}", result.destination_reached);
/// println!("Total hops: {}", result.hop_count());
///
/// for hop in &result.hops {
///     if let Some(addr) = hop.addr {
///         println!("Hop {}: {} ({:?})", hop.ttl, addr, hop.hostname);
///     }
/// }
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracerouteResult {
    /// Target hostname as provided
    pub target: String,
    /// Resolved target IP address
    pub target_ip: IpAddr,
    /// All hops discovered during the traceroute
    pub hops: Vec<ClassifiedHopInfo>,
    /// ISP information if detected
    pub isp_info: Option<IspInfo>,
    /// Protocol actually used for probing (may differ from requested)
    pub protocol_used: ProbeProtocol,
    /// Socket mode actually used
    pub socket_mode_used: SocketMode,
    /// Whether the destination was reached
    pub destination_reached: bool,
    /// Total duration of the traceroute operation
    pub total_duration: std::time::Duration,
}

impl TracerouteResult {
    /// Get the number of hops discovered
    pub fn hop_count(&self) -> usize {
        self.hops.len()
    }

    /// Get the final hop that reached the destination, if any
    ///
    /// Returns the hop information for the probe that reached the target IP.
    pub fn destination_hop(&self) -> Option<&ClassifiedHopInfo> {
        self.hops
            .iter()
            .find(|hop| hop.is_destination(self.target_ip))
    }

    /// Get the maximum TTL value used
    ///
    /// Returns the highest TTL value among all discovered hops.
    pub fn max_ttl(&self) -> Option<u8> {
        self.hops.iter().map(|h| h.ttl).max()
    }

    /// Check if a specific TTL had a response
    ///
    /// Returns true if any hop with the given TTL received a response.
    pub fn has_response_at_ttl(&self, ttl: u8) -> bool {
        self.hops.iter().any(|h| h.ttl == ttl && h.addr.is_some())
    }

    /// Get all hops with ASN information
    ///
    /// Returns a vector of references to hops that have ASN data available.
    pub fn hops_with_asn(&self) -> Vec<&ClassifiedHopInfo> {
        self.hops.iter().filter(|h| h.asn_info.is_some()).collect()
    }

    /// Get all hops within a specific network segment
    ///
    /// Filter hops by their network segment classification (e.g., LAN, WAN, etc.).
    pub fn hops_in_segment(
        &self,
        segment: crate::traceroute::SegmentType,
    ) -> Vec<&ClassifiedHopInfo> {
        self.hops.iter().filter(|h| h.segment == segment).collect()
    }

    /// Calculate average RTT across all responding hops
    ///
    /// Returns the mean round-trip time in milliseconds for all hops that responded.
    pub fn average_rtt_ms(&self) -> Option<f64> {
        let rtts: Vec<f64> = self
            .hops
            .iter()
            .filter_map(super::types::ClassifiedHopInfo::rtt_ms)
            .collect();

        if rtts.is_empty() {
            None
        } else {
            Some(rtts.iter().sum::<f64>() / rtts.len() as f64)
        }
    }
}

/// Progress information during a traceroute operation
///
/// Provides real-time status updates during a traceroute. Can be used
/// to display progress bars or status information in UIs.
///
/// # Note
///
/// The `run_with_progress()` method that would use this for streaming updates
/// is not yet fully implemented. Currently, you can only get progress snapshots
/// via `Traceroute::get_progress()`.
///
/// # Examples
///
/// ```
/// # use ftr::TracerouteProgress;
/// # use std::time::Duration;
/// let progress = TracerouteProgress {
///     current_ttl: 15,
///     max_ttl: 30,
///     hops_discovered: 12,
///     destination_reached: false,
///     elapsed: Duration::from_secs(2),
/// };
///
/// println!("Progress: {:.1}%", progress.percentage());
/// println!("Complete: {}", progress.is_complete());
/// ```
#[derive(Debug, Clone)]
pub struct TracerouteProgress {
    /// Current TTL being probed
    pub current_ttl: u8,
    /// Maximum TTL to probe
    pub max_ttl: u8,
    /// Number of hops discovered so far
    pub hops_discovered: usize,
    /// Whether the destination has been reached
    pub destination_reached: bool,
    /// Elapsed time since start
    pub elapsed: std::time::Duration,
}

impl TracerouteProgress {
    /// Calculate progress percentage
    ///
    /// Returns a value between 0.0 and 100.0 representing completion percentage.
    pub fn percentage(&self) -> f32 {
        if self.destination_reached {
            100.0
        } else {
            (self.current_ttl as f32 / self.max_ttl as f32) * 100.0
        }
    }

    /// Check if the traceroute is complete
    ///
    /// Returns true if either the destination was reached or the maximum TTL was exceeded.
    pub fn is_complete(&self) -> bool {
        self.destination_reached || self.current_ttl >= self.max_ttl
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traceroute::{AsnInfo, SegmentType};
    use std::net::Ipv4Addr;
    use std::time::Duration;

    fn create_test_result() -> TracerouteResult {
        let hops = vec![
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
                    name: "Example ISP".to_string(),
                }),
                rtt: Some(Duration::from_millis(15)),
            },
            ClassifiedHopInfo {
                ttl: 3,
                segment: SegmentType::Beyond,
                hostname: Some("google.com".to_string()),
                addr: Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
                asn_info: Some(AsnInfo {
                    asn: 15169,
                    prefix: "8.8.8.0/24".to_string(),
                    country_code: "US".to_string(),
                    registry: "ARIN".to_string(),
                    name: "GOOGLE".to_string(),
                }),
                rtt: Some(Duration::from_millis(25)),
            },
        ];

        TracerouteResult {
            target: "google.com".to_string(),
            target_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            hops,
            isp_info: Some(IspInfo {
                public_ip: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
                asn: 12345,
                name: "Example ISP".to_string(),
            }),
            protocol_used: ProbeProtocol::Icmp,
            socket_mode_used: SocketMode::Raw,
            destination_reached: true,
            total_duration: Duration::from_millis(500),
        }
    }

    #[test]
    fn test_traceroute_result() {
        let result = create_test_result();

        assert_eq!(result.hop_count(), 3);
        assert_eq!(result.max_ttl(), Some(3));
        assert!(result.destination_reached);
        assert!(result.has_response_at_ttl(2));
        assert!(!result.has_response_at_ttl(4));

        let dest_hop = result.destination_hop();
        assert!(dest_hop.is_some());
        assert_eq!(dest_hop.unwrap().ttl, 3);

        let asn_hops = result.hops_with_asn();
        assert_eq!(asn_hops.len(), 2);

        let isp_hops = result.hops_in_segment(SegmentType::Isp);
        assert_eq!(isp_hops.len(), 1);

        let avg_rtt = result.average_rtt_ms();
        assert!(avg_rtt.is_some());
        assert_eq!(avg_rtt.unwrap(), 15.0); // (5 + 15 + 25) / 3
    }

    #[test]
    fn test_traceroute_progress() {
        let mut progress = TracerouteProgress {
            current_ttl: 5,
            max_ttl: 30,
            hops_discovered: 4,
            destination_reached: false,
            elapsed: Duration::from_secs(2),
        };

        assert!(!progress.is_complete());
        assert!(progress.percentage() > 16.0 && progress.percentage() < 17.0);

        progress.destination_reached = true;
        assert!(progress.is_complete());
        assert_eq!(progress.percentage(), 100.0);

        progress.destination_reached = false;
        progress.current_ttl = 30;
        assert!(progress.is_complete());
    }
}
