//! Example demonstrating the new service-oriented API

use ftr::Ftr;
use std::net::IpAddr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create an Ftr instance with default services
    let ftr = Ftr::new();

    // Example 1: Simple ASN lookup
    println!("=== ASN Lookup Example ===");
    let ip: IpAddr = "8.8.8.8".parse()?;
    match ftr.lookup_asn(ip).await {
        Ok(asn_info) => {
            println!("IP: {}", ip);
            println!("ASN: AS{}", asn_info.asn);
            println!("Organization: {}", asn_info.name);
            println!("Country: {}", asn_info.country_code);
            println!("Prefix: {}", asn_info.prefix);
        }
        Err(e) => println!("ASN lookup failed: {}", e),
    }

    // Example 2: Reverse DNS lookup
    println!("\n=== Reverse DNS Example ===");
    let dns_ip: IpAddr = "1.1.1.1".parse()?;
    match ftr.lookup_rdns(dns_ip).await {
        Ok(hostname) => {
            println!("{} -> {}", dns_ip, hostname);
        }
        Err(e) => println!("Reverse DNS lookup failed: {}", e),
    }

    // Example 3: Public IP detection
    println!("\n=== Public IP Detection ===");
    match ftr.get_public_ip().await {
        Ok(public_ip) => {
            println!("Your public IP: {}", public_ip);

            // Look up information about our own public IP
            if let Ok(asn_info) = ftr.lookup_asn(public_ip).await {
                println!("Your ISP: {}", asn_info.name);
                println!("Your ASN: AS{}", asn_info.asn);
            }
        }
        Err(e) => println!("Public IP detection failed: {}", e),
    }

    // Example 4: Direct service access for advanced usage
    println!("\n=== Advanced Service Usage ===");
    {
        // Access the ASN service directly (no locking needed)
        let asn_service = &ftr.services.asn;

        // Check cache stats
        let stats = asn_service.cache_stats().await;
        println!("ASN cache has {} entries", stats.entries);

        // Check if an IP is cached
        let test_ip: IpAddr = "8.8.8.8".parse()?;
        // Note: is_cached still uses Ipv4Addr internally
        if let IpAddr::V4(ipv4) = test_ip {
            if asn_service.is_cached(&ipv4).await {
                println!("{} is in the ASN cache", test_ip);
            }
        }
    }

    // Example 5: Cache management
    println!("\n=== Cache Management ===");
    println!("Clearing all caches...");
    ftr.clear_all_caches().await;
    println!("All caches cleared!");

    Ok(())
}
