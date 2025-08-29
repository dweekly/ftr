// Test program to exercise the v0.6.0 library API and verify JSON output
use ftr::{Ftr, TracerouteConfig, SegmentType};
use serde_json;
use std::error::Error;

#[derive(serde::Serialize)]
struct JsonHop {
    ttl: u8,
    segment: Option<String>,
    address: Option<String>,
    hostname: Option<String>,
    asn_info: Option<ftr::AsnInfo>,
    rtt_ms: Option<f64>,
}

#[derive(serde::Serialize)]
struct JsonOutput {
    version: String,
    target: String,
    target_ip: String,
    public_ip: Option<String>,
    isp: Option<ftr::IspInfo>,
    hops: Vec<JsonHop>,
    destination_reached: bool,
    total_hops: usize,
    total_duration_ms: f64,
    socket_mode_used: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    println!("=== Testing ftr v0.6.0 Library API ===\n");

    // Create an Ftr instance
    let ftr = Ftr::new();
    
    // Test target
    let target = "google.com";
    
    println!("1. Testing with enrichment enabled (default)");
    println!("   Target: {}", target);
    
    // Create config with enrichment
    let config = TracerouteConfig::builder()
        .target(target)
        .max_hops(30)
        .build()?;
    
    // Perform traceroute
    let result = ftr.trace_with_config(config).await?;
    
    println!("\n   === Library Results ===");
    println!("   Target: {} ({})", result.target, result.target_ip);
    println!("   Destination reached: {}", result.destination_reached);
    println!("   Total hops: {}", result.hop_count());
    println!("   Duration: {:?}", result.total_duration);
    
    // Display ISP info if available
    if let Some(ref isp) = result.isp_info {
        println!("   Detected ISP: AS{} ({})", 
            isp.asn, isp.name);
    }
    
    // Display hops with new segment types
    println!("\n   Hops with v0.6.0 segments:");
    for hop in &result.hops {
        if let Some(addr) = hop.addr {
            let segment_str = match hop.segment {
                SegmentType::Lan => "LAN",
                SegmentType::Isp => "ISP", 
                SegmentType::Transit => "TRANSIT",
                SegmentType::Destination => "DESTINATION",
                SegmentType::Unknown => "UNKNOWN",
            };
            
            let hostname = hop.hostname.as_deref().unwrap_or("");
            let rtt = hop.rtt_ms().map_or("*".to_string(), |ms| format!("{:.3} ms", ms));
            
            let asn_str = if let Some(ref asn_info) = hop.asn_info {
                if asn_info.asn != 0 {
                    format!(" [AS{} - {}, {}]", asn_info.asn, asn_info.name, asn_info.country_code)
                } else {
                    " [Private Network]".to_string()
                }
            } else {
                String::new()
            };
            
            println!("   {:2} [{:11}] {} {} {}{}",
                hop.ttl, segment_str, addr, hostname, rtt, asn_str);
        } else {
            println!("   {:2} *", hop.ttl);
        }
    }
    
    // Build JSON output structure matching CLI
    println!("\n   === JSON Output (Library) ===");
    let json_output = JsonOutput {
        version: "0.6.0".to_string(),
        target: result.target.clone(),
        target_ip: result.target_ip.to_string(),
        public_ip: None, // public_ip is not directly on TracerouteResult
        isp: result.isp_info.clone(),
        hops: result.hops.iter().map(|hop| {
            JsonHop {
                ttl: hop.ttl,
                segment: match hop.segment {
                    SegmentType::Lan => Some("LAN".to_string()),
                    SegmentType::Isp => Some("ISP".to_string()),
                    SegmentType::Transit => Some("TRANSIT".to_string()),
                    SegmentType::Destination => Some("DESTINATION".to_string()),
                    SegmentType::Unknown => None,
                },
                address: hop.addr.map(|a| a.to_string()),
                hostname: hop.hostname.clone(),
                asn_info: hop.asn_info.clone(),
                rtt_ms: hop.rtt_ms(),
            }
        }).collect(),
        destination_reached: result.destination_reached,
        total_hops: result.hop_count(),
        total_duration_ms: result.total_duration.as_millis() as f64,
        socket_mode_used: result.socket_mode_used.description().to_string(),
    };
    
    let json_string = serde_json::to_string_pretty(&json_output)?;
    println!("{}", json_string);
    
    // Test counting by segment type
    println!("\n   === Segment Analysis ===");
    let lan_hops = result.hops_in_segment(SegmentType::Lan);
    let isp_hops = result.hops_in_segment(SegmentType::Isp);
    let transit_hops = result.hops_in_segment(SegmentType::Transit);
    let dest_hops = result.hops_in_segment(SegmentType::Destination);
    let unknown_hops = result.hops_in_segment(SegmentType::Unknown);
    
    println!("   LAN hops: {}", lan_hops.len());
    println!("   ISP hops: {}", isp_hops.len());
    println!("   TRANSIT hops: {}", transit_hops.len());
    println!("   DESTINATION hops: {}", dest_hops.len());
    println!("   UNKNOWN hops: {}", unknown_hops.len());
    
    // Now test without enrichment
    println!("\n2. Testing with enrichment disabled");
    let config_no_enrich = TracerouteConfig::builder()
        .target(target)
        .max_hops(30)
        .enable_asn_lookup(false)
        .enable_rdns(false)
        .build()?;
    
    let result_no_enrich = ftr.trace_with_config(config_no_enrich).await?;
    
    println!("   Hops without enrichment:");
    for hop in &result_no_enrich.hops {
        if let Some(addr) = hop.addr {
            let hostname = hop.hostname.as_deref().unwrap_or("");
            let rtt = hop.rtt_ms().map_or("*".to_string(), |ms| format!("{:.3} ms", ms));
            
            // Without enrichment, segment should be Unknown
            println!("   {:2} {} {} {} (segment: {:?})",
                hop.ttl, addr, hostname, rtt, hop.segment);
        } else {
            println!("   {:2} *", hop.ttl);
        }
    }
    
    // Test a route that might have TRANSIT hops
    println!("\n3. Testing route with potential TRANSIT hops");
    let transit_target = "yahoo.com";
    
    let config_transit = TracerouteConfig::builder()
        .target(transit_target)
        .max_hops(30)
        .build()?;
    
    let result_transit = ftr.trace_with_config(config_transit).await?;
    
    println!("   Target: {} ({})", result_transit.target, result_transit.target_ip);
    
    // Look specifically for TRANSIT and DESTINATION segments
    let mut found_transit = false;
    let mut found_destination = false;
    
    for hop in &result_transit.hops {
        if hop.segment == SegmentType::Transit {
            found_transit = true;
            if let Some(addr) = hop.addr {
                println!("   Found TRANSIT hop: TTL {} - {} {:?}", 
                    hop.ttl, addr, hop.asn_info);
            }
        }
        if hop.segment == SegmentType::Destination {
            found_destination = true;
            if let Some(addr) = hop.addr {
                println!("   Found DESTINATION hop: TTL {} - {} {:?}", 
                    hop.ttl, addr, hop.asn_info);
            }
        }
    }
    
    if !found_transit {
        println!("   No TRANSIT hops found (direct path or couldn't determine)");
    }
    if !found_destination {
        println!("   No DESTINATION hops found (couldn't determine destination ASN)");
    }
    
    println!("\n=== Test Complete ===");
    
    Ok(())
}