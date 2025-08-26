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
use std::time::{Duration, Instant};

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
    #[clap(short, long, default_value_t = 33434)]
    port: u16,

    /// Specify public IP address (skip STUN detection)
    #[clap(long)]
    public_ip: Option<String>,

    /// Custom STUN server address (e.g., stun.l.google.com:19302)
    #[clap(long)]
    stun_server: Option<String>,
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
    path_label: Option<String>,
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

fn main() {
    let process_start = Instant::now();

    // Quick check for help/version before starting async runtime
    let args: Vec<String> = std::env::args().collect();
    if args.len() == 2 && (args[1] == "--help" || args[1] == "-h") {
        // Clap will handle this
        let _ = Args::parse();
        return;
    }
    if args.len() == 2 && (args[1] == "--version" || args[1] == "-V") {
        println!("ftr {}", get_version());
        return;
    }

    // Create single-threaded tokio runtime for lower overhead
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("Failed to create Tokio runtime");

    let result = runtime.block_on(async_main(process_start));

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

async fn async_main(_process_start: Instant) -> Result<()> {
    let args = Args::parse();

    // Create Ftr instance with fresh caches
    let ftr_instance = ftr::Ftr::new();

    // Handle public IP option - skip STUN if provided
    if args.public_ip.is_none() {
        // Set custom STUN server if provided
        if let Some(stun_server) = &args.stun_server {
            std::env::set_var("FTR_STUN_SERVER", stun_server);
        }

        // Pre-warm STUN cache immediately for faster public IP detection
        // (Cache warming is now handled internally by Ftr instance)
    }

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
    if !ftr::socket::utils::is_root() && !ftr::socket::utils::has_non_root_capability() {
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

    // Pre-fetch destination IP's rDNS and ASN lookups in the background
    {
        let target_ip_clone = target_ip;
        let no_rdns = args.no_rdns;
        tokio::spawn(async move {
            // Pre-warm DNS reverse lookup only if rDNS is enabled
            if !no_rdns {
                use hickory_resolver::name_server::TokioConnectionProvider;
                use hickory_resolver::{config::ResolverConfig, TokioResolver};
                let resolver = TokioResolver::builder_with_config(
                    ResolverConfig::cloudflare(),
                    TokioConnectionProvider::default(),
                )
                .build();
                let _ = resolver.reverse_lookup(target_ip_clone).await;
            }

            // ASN pre-warming removed - caches are now managed by Ftr instance
        });
    }

    // Parse public IP if provided
    let public_ip = if let Some(ip_str) = &args.public_ip {
        match ip_str.parse::<IpAddr>() {
            Ok(ip) => Some(ip),
            Err(_) => {
                eprintln!("Error: Invalid public IP address: {}", ip_str);
                std::process::exit(1);
            }
        }
    } else {
        None
    };

    // Build configuration
    let mut builder = TracerouteConfigBuilder::new()
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
        .verbose(args.verbose)
        .port(args.port);

    // Add public IP if provided
    if let Some(ip) = public_ip {
        builder = builder.public_ip(ip);
    }

    let config = builder.build();

    let config = match config {
        Ok(mut cfg) => {
            // Add protocol and mode if specified
            cfg.protocol = preferred_protocol;
            cfg.socket_mode = preferred_mode;

            // Warn Windows users about potential issues with short timeouts + enrichment
            #[cfg(target_os = "windows")]
            if args.probe_timeout_ms < 100 && (!args.no_enrich || !args.no_rdns) {
                eprintln!(
                    "Warning: On Windows, probe timeouts < 100ms with enrichment enabled may cause"
                );
                eprintln!(
                    "         unreliable results. Consider using --probe-timeout-ms 100 or higher,"
                );
                eprintln!("         or disable enrichment with --no-enrich --no-rdns");
                eprintln!();
            }

            cfg
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };

    // Warn if port was explicitly specified but won't be used
    if args.port != 33434 && preferred_protocol == Some(ProbeProtocol::Icmp) {
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

    // Run traceroute using the Ftr instance
    let result = match ftr_instance.trace_with_config(config).await {
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
        display_text_results(result, args.no_enrich, args.no_rdns);
    }

    // Quick exit to avoid cleanup overhead on Windows
    std::process::exit(0);
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
    let labels = result.path_labels();
    for (i, hop) in result.hops.iter().enumerate() {
        let path_label = labels.get(i).and_then(|o| o.as_ref()).map(|l| match l {
            ftr::PathLabel::Destination => "DESTINATION".to_string(),
            ftr::PathLabel::Transit => "TRANSIT".to_string(),
        });
        json_output.hops.push(JsonHop {
            ttl: hop.ttl,
            segment: Some(format!("{:?}", hop.segment)),
            address: hop.addr.map(|a| a.to_string()),
            hostname: hop.hostname.clone(),
            asn_info: hop.asn_info.clone(),
            rtt_ms: hop.rtt_ms(),
            path_label,
        });
    }

    println!("{}", serde_json::to_string_pretty(&json_output)?);
    Ok(())
}

/// Display results in text format
fn display_text_results(result: TracerouteResult, no_enrich: bool, no_rdns: bool) {
    // Use the explicit no_enrich flag passed from command line args
    let enrichment_disabled = no_enrich;

    // Display hops
    let labels = result.path_labels();
    for (idx, hop) in result.hops.iter().enumerate() {
        if hop.addr.is_none() {
            // Silent hop
            println!("{:2}", hop.ttl);
        } else {
            let addr_str = hop.addr.map_or("*".to_string(), |a| a.to_string());
            let rtt_str = hop
                .rtt_ms()
                .map_or("*".to_string(), |r| format!("{:.3} ms", r));

            // Format hostname and address
            let host_display = if !no_rdns && hop.hostname.is_some() {
                let hostname = hop.hostname.as_ref().expect("hostname checked above");
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
                    // Check if name already ends with country code
                    if asn_info
                        .name
                        .ends_with(&format!(", {}", asn_info.country_code))
                    {
                        format!(" [AS{} - {}]", asn_info.asn, asn_info.name)
                    } else {
                        format!(
                            " [AS{} - {}, {}]",
                            asn_info.asn, asn_info.name, asn_info.country_code
                        )
                    }
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
                let role_str = labels
                    .get(idx)
                    .and_then(|o| o.as_ref())
                    .map(|l| match l {
                        ftr::PathLabel::Destination => " | DESTINATION",
                        ftr::PathLabel::Transit => " | TRANSIT",
                    })
                    .unwrap_or("");
                println!(
                    "{:2} [{}{}] {} {}{}",
                    hop.ttl, hop.segment, role_str, host_display, rtt_str, asn_str
                );
            }
        }
    }

    // Display ISP info if available
    if let Some(isp_info) = &result.isp_info {
        if !no_rdns && isp_info.hostname.is_some() {
            println!(
                "\nDetected public IP: {} ({})",
                isp_info.public_ip,
                isp_info.hostname.as_ref().expect("hostname checked above")
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
