//! ftr - Fast TraceRoute: A parallel ICMP traceroute implementation with ASN lookup.
//!
//! This is the command-line interface for the ftr library.

#![allow(clippy::single_match)]
#![allow(clippy::nonminimal_bool)]
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::needless_pass_by_value)]

use anyhow::Result;
use clap::Parser;
use ftr::{ProbeProtocol, SocketMode, TracerouteConfigBuilder, TracerouteError, TracerouteResult};
use std::net::IpAddr;
use std::time::Duration;

/// Get the version string for ftr
fn get_version() -> &'static str {
    if cfg!(debug_assertions) {
        concat!(env!("CARGO_PKG_VERSION"), "-UNRELEASED")
    } else {
        env!("CARGO_PKG_VERSION")
    }
}

/// Command-line arguments for the traceroute tool.
#[derive(Parser, Debug)]
#[clap(author, version, about = "Fast parallel ICMP traceroute with ASN lookup", long_about = None)]
struct Args {
    /// Target hostname or IP address
    host: String,

    /// Starting TTL value
    #[clap(short, long, default_value_t = 1)]
    start_ttl: u8,

    /// Maximum number of hops
    #[clap(short = 'm', long, default_value_t = 30)]
    max_hops: u8,

    /// Timeout for individual probes in milliseconds
    #[clap(long, default_value_t = 1000)]
    probe_timeout_ms: u64,

    /// Interval between launching probes in milliseconds (applies to both inter-TTL and inter-query delays)
    #[clap(short = 'i', long, default_value_t = 0)]
    send_launch_interval_ms: u64,

    /// Overall timeout for the traceroute in milliseconds
    #[clap(short = 'W', long, default_value_t = 3000)]
    overall_timeout_ms: u64,

    /// Disable ASN lookup and segment classification
    #[clap(long)]
    no_enrich: bool,

    /// Disable reverse DNS lookups
    #[clap(long)]
    no_rdns: bool,

    /// Protocol to use (icmp, udp)
    #[clap(long, value_enum)]
    protocol: Option<ProtocolArg>,

    /// Socket mode to use (raw, dgram)
    #[clap(long, value_enum)]
    socket_mode: Option<SocketModeArg>,

    /// Number of probes per hop
    #[clap(short = 'q', long, default_value_t = 1)]
    queries: u8,

    /// Output results in JSON format
    #[clap(long)]
    json: bool,

    /// Enable verbose output (use -vv for debug timestamps)
    #[clap(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Target port for UDP/TCP modes
    #[clap(short, long, default_value_t = 443)]
    port: u16,

    /// Use async implementation (experimental, Windows only)
    #[cfg(feature = "async")]
    #[clap(long)]
    async_mode: bool,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum ProtocolArg {
    Icmp,
    Udp,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum SocketModeArg {
    Raw,
    Dgram,
}

/// JSON output structure for a single hop
#[derive(Debug, serde::Serialize)]
struct JsonHop {
    ttl: u8,
    segment: Option<String>,
    address: Option<String>,
    hostname: Option<String>,
    asn_info: Option<ftr::AsnInfo>,
    rtt_ms: Option<f64>,
}

/// JSON output structure for the entire traceroute result
#[derive(Debug, serde::Serialize)]
struct JsonOutput {
    version: String,
    target: String,
    target_ip: String,
    public_ip: Option<String>,
    isp: Option<JsonIsp>,
    hops: Vec<JsonHop>,
    protocol: String,
    socket_mode: String,
}

/// JSON output structure for ISP information
#[derive(Debug, serde::Serialize)]
struct JsonIsp {
    asn: String,
    name: String,
    hostname: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Check if user is asking for version explicitly
    if std::env::args().any(|arg| arg == "--version" || arg == "-V") {
        println!("ftr {}", get_version());
        std::process::exit(0);
    }

    let args = Args::parse();

    // Initialize debug mode if requested
    // ftr::debug::init_debug(args.verbose);

    // Validate arguments
    if args.start_ttl < 1 {
        eprintln!("Error: start-ttl must be at least 1");
        std::process::exit(1);
    }

    if args.probe_timeout_ms == 0 {
        eprintln!("Error: probe-timeout-ms must be greater than 0");
        std::process::exit(1);
    }

    // Check if running without root on a platform that requires it
    if !ftr::socket::factory::is_root() && !ftr::socket::factory::has_non_root_capability() {
        eprintln!(
            "Error: ftr requires root privileges on {}",
            std::env::consts::OS
        );
        eprintln!("This platform does not support unprivileged traceroute.");
        eprintln!(
            "Please run with sudo: sudo {}",
            std::env::args().collect::<Vec<_>>().join(" ")
        );
        #[cfg(any(target_os = "freebsd", target_os = "openbsd"))]
        eprintln!(
            "Or make the binary setuid root: sudo chown root:wheel ftr && sudo chmod u+s ftr"
        );
        std::process::exit(1);
    }

    // Convert command-line args to library types
    let preferred_protocol = args.protocol.map(|p| match p {
        ProtocolArg::Icmp => ProbeProtocol::Icmp,
        ProtocolArg::Udp => ProbeProtocol::Udp,
    });

    let preferred_mode = args.socket_mode.map(|m| match m {
        SocketModeArg::Raw => SocketMode::Raw,
        SocketModeArg::Dgram => SocketMode::Dgram,
    });

    // Resolve target early to use in config
    let target_ip = resolve_target(&args.host).await?;

    // Build configuration
    let config = TracerouteConfigBuilder::new()
        .target(&args.host)
        .target_ip(target_ip)
        .start_ttl(args.start_ttl)
        .max_hops(args.max_hops)
        .probe_timeout(Duration::from_millis(args.probe_timeout_ms))
        .send_interval(Duration::from_millis(args.send_launch_interval_ms))
        .overall_timeout(Duration::from_millis(args.overall_timeout_ms))
        .queries_per_hop(args.queries)
        .enable_asn_lookup(!args.no_enrich)
        .enable_rdns(!args.no_rdns)
        .verbose(args.verbose > 0)
        .port(args.port)
        .build();

    let config = match config {
        Ok(mut cfg) => {
            // Add protocol and mode if specified
            cfg.protocol = preferred_protocol;
            cfg.socket_mode = preferred_mode;
            cfg
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };

    // Warn if port was specified but won't be used
    if args.port != 443 && preferred_protocol == Some(ProbeProtocol::Icmp) {
        eprintln!(
            "Warning: Port {} specified but will be ignored for ICMP protocol",
            args.port
        );
    }

    // Print initial message
    if !args.json {
        println!(
            "ftr to {} ({}), {} max hops, {}ms probe timeout, {}ms overall timeout{}",
            args.host,
            target_ip,
            args.max_hops,
            args.probe_timeout_ms,
            args.overall_timeout_ms,
            if args.no_enrich {
                " (enrichment disabled)"
            } else {
                ""
            }
        );

        if !args.no_enrich {
            println!(
                "\nPerforming ASN lookups{} and classifying segments...",
                if args.no_rdns {
                    ""
                } else {
                    ", reverse DNS lookups"
                }
            );
        } else {
            println!("\nTraceroute path (raw):");
        }
    }

    // Run traceroute
    #[cfg(feature = "async")]
    let result = if args.async_mode {
        // Use async implementation
        if !args.json {
            println!("Using async implementation (experimental)...\n");
        }
        match ftr::traceroute::async_api::trace_with_config_async(config).await {
            Ok(result) => result,
            Err(TracerouteError::InsufficientPermissions {
                required,
                suggestion,
            }) => {
                eprintln!("\nError: Insufficient permissions");
                eprintln!("Required: {}", required);
                eprintln!("Suggestion: {}", suggestion);
                eprintln!(
                    "\nTo run with elevated privileges: sudo {}",
                    std::env::args().collect::<Vec<_>>().join(" ")
                );
                std::process::exit(1);
            }
            Err(TracerouteError::NotImplemented { feature }) => {
                eprintln!("\nError: {} is not yet implemented", feature);
                eprintln!("This feature is planned for a future release.");
                std::process::exit(1);
            }
            Err(TracerouteError::Ipv6NotSupported) => {
                eprintln!("\nError: IPv6 targets are not yet supported");
                eprintln!("Please use an IPv4 address or hostname that resolves to IPv4.");
                std::process::exit(1);
            }
            Err(TracerouteError::ResolutionError(msg)) => {
                eprintln!("\nError: {}", msg);
                eprintln!("Please check the hostname and your network connection.");
                std::process::exit(1);
            }
            Err(TracerouteError::ConfigError(msg)) => {
                eprintln!("\nError: Invalid configuration - {}", msg);
                eprintln!("Run 'ftr --help' for usage information.");
                std::process::exit(1);
            }
            Err(e) => {
                eprintln!("\nError: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        // Use standard implementation
        match ftr::trace_with_config(config).await {
            Ok(result) => result,
            Err(TracerouteError::InsufficientPermissions {
                required,
                suggestion,
            }) => {
                eprintln!("\nError: Insufficient permissions");
                eprintln!("Required: {}", required);
                eprintln!("Suggestion: {}", suggestion);
                eprintln!(
                    "\nTo run with elevated privileges: sudo {}",
                    std::env::args().collect::<Vec<_>>().join(" ")
                );
                std::process::exit(1);
            }
            Err(TracerouteError::NotImplemented { feature }) => {
                eprintln!("\nError: {} is not yet implemented", feature);
                eprintln!("This feature is planned for a future release.");
                std::process::exit(1);
            }
            Err(TracerouteError::Ipv6NotSupported) => {
                eprintln!("\nError: IPv6 targets are not yet supported");
                eprintln!("Please use an IPv4 address or hostname that resolves to IPv4.");
                std::process::exit(1);
            }
            Err(TracerouteError::ResolutionError(msg)) => {
                eprintln!("\nError: {}", msg);
                eprintln!("Please check the hostname and your network connection.");
                std::process::exit(1);
            }
            Err(TracerouteError::ConfigError(msg)) => {
                eprintln!("\nError: Invalid configuration - {}", msg);
                eprintln!("Run 'ftr --help' for usage information.");
                std::process::exit(1);
            }
            Err(e) => {
                eprintln!("\nError: {}", e);
                std::process::exit(1);
            }
        }
    };

    #[cfg(not(feature = "async"))]
    let result = match ftr::trace_with_config(config).await {
        Ok(result) => result,
        Err(TracerouteError::InsufficientPermissions {
            required,
            suggestion,
        }) => {
            eprintln!("\nError: Insufficient permissions");
            eprintln!("Required: {}", required);
            eprintln!("Suggestion: {}", suggestion);
            eprintln!(
                "\nTo run with elevated privileges: sudo {}",
                std::env::args().collect::<Vec<_>>().join(" ")
            );
            std::process::exit(1);
        }
        Err(TracerouteError::NotImplemented { feature }) => {
            eprintln!("\nError: {} is not yet implemented", feature);
            eprintln!("This feature is planned for a future release.");
            std::process::exit(1);
        }
        Err(TracerouteError::Ipv6NotSupported) => {
            eprintln!("\nError: IPv6 targets are not yet supported");
            eprintln!("Please use an IPv4 address or hostname that resolves to IPv4.");
            std::process::exit(1);
        }
        Err(TracerouteError::ResolutionError(msg)) => {
            eprintln!("\nError: {}", msg);
            eprintln!("Please check the hostname and your network connection.");
            std::process::exit(1);
        }
        Err(TracerouteError::ConfigError(msg)) => {
            eprintln!("\nError: Invalid configuration - {}", msg);
            eprintln!("Run 'ftr --help' for usage information.");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("\nError: {}", e);
            std::process::exit(1);
        }
    };

    // Display results
    if args.json {
        display_json_results(result)?;
    } else {
        display_text_results(result);
    }

    Ok(())
}

/// Resolve target hostname to IP address
async fn resolve_target(host: &str) -> Result<IpAddr> {
    // Try parsing as IP first
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(ip);
    }

    // Use DNS resolution
    use hickory_resolver::config::ResolverConfig;
    use hickory_resolver::name_server::TokioConnectionProvider;
    use hickory_resolver::TokioResolver;

    let resolver = TokioResolver::builder_with_config(
        ResolverConfig::cloudflare(),
        TokioConnectionProvider::default(),
    )
    .build();

    // Try IPv4 first
    if let Ok(lookup) = resolver.ipv4_lookup(host).await {
        if let Some(ipv4) = lookup.iter().next() {
            return Ok(IpAddr::V4(ipv4.0));
        }
    }

    // Try IPv6
    if let Ok(lookup) = resolver.ipv6_lookup(host).await {
        if let Some(ipv6) = lookup.iter().next() {
            return Ok(IpAddr::V6(ipv6.0));
        }
    }

    anyhow::bail!("Error resolving host: {}", host)
}

/// Display results in JSON format
fn display_json_results(result: TracerouteResult) -> Result<()> {
    let mut json_output = JsonOutput {
        version: get_version().to_string(),
        target: result.target.clone(),
        target_ip: result.target_ip.to_string(),
        public_ip: result.isp_info.as_ref().map(|i| i.public_ip.to_string()),
        isp: result.isp_info.as_ref().map(|i| JsonIsp {
            asn: i.asn.to_string(),
            name: i.name.clone(),
            hostname: i.hostname.clone(),
        }),
        hops: Vec::new(),
        protocol: result.protocol_used.description().to_string(),
        socket_mode: result.socket_mode_used.description().to_string(),
    };

    // Convert hops to JSON format
    for hop in &result.hops {
        json_output.hops.push(JsonHop {
            ttl: hop.ttl,
            segment: Some(format!("{:?}", hop.segment)),
            address: hop.addr.map(|a| a.to_string()),
            hostname: hop.hostname.clone(),
            asn_info: hop.asn_info.clone(),
            rtt_ms: hop.rtt_ms(),
        });
    }

    println!("{}", serde_json::to_string_pretty(&json_output)?);
    Ok(())
}

/// Display results in text format
fn display_text_results(result: TracerouteResult) {
    // Check if enrichment was disabled by looking at whether ANY hop has ASN info
    // If enrichment is disabled, no hops should have ASN info
    let enrichment_disabled = result.hops.iter().all(|h| h.asn_info.is_none());

    // Display hops
    for hop in &result.hops {
        if hop.addr.is_none() {
            // Silent hop
            println!("{:2}", hop.ttl);
        } else {
            let addr_str = hop.addr.map_or("*".to_string(), |a| a.to_string());
            let rtt_str = hop
                .rtt_ms()
                .map_or("*".to_string(), |r| format!("{:.3} ms", r));

            // Format hostname and address
            let host_display = if let Some(hostname) = &hop.hostname {
                if hop.addr.is_some() {
                    format!("{} ({})", hostname, addr_str)
                } else {
                    hostname.clone()
                }
            } else {
                addr_str.clone()
            };

            // Format ASN info
            let asn_str = if let Some(asn_info) = &hop.asn_info {
                if asn_info.asn != 0 {
                    format!(
                        " [AS{} - {}, {}]",
                        asn_info.asn, asn_info.name, asn_info.country_code
                    )
                } else {
                    format!(" [{}]", asn_info.name)
                }
            } else {
                String::new()
            };

            // Only show segment and ASN if enrichment was enabled
            if enrichment_disabled {
                // Raw mode - no enrichment data at all
                println!("{:2} {} {}", hop.ttl, host_display, rtt_str);
            } else {
                // Enriched mode - show segment and ASN info
                println!(
                    "{:2} [{}] {} {}{}",
                    hop.ttl, hop.segment, host_display, rtt_str, asn_str
                );
            }
        }
    }

    // Display ISP info if available
    if let Some(isp_info) = &result.isp_info {
        if let Some(hostname) = &isp_info.hostname {
            println!(
                "\nDetected public IP: {} ({})",
                isp_info.public_ip, hostname
            );
        } else {
            println!("\nDetected public IP: {}", isp_info.public_ip);
        }
        println!("Detected ISP: AS{} ({})", isp_info.asn, isp_info.name);
    }
}

#[cfg(test)]
#[path = "main_tests.rs"]
mod main_tests;
