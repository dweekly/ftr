//! System DNS resolver discovery
//!
//! On Unix, the system's configured resolvers are discovered by parsing
//! `/etc/resolv.conf` (see resolv.conf(5)). The parse itself is a pure
//! function on a string ([`parse_resolv_conf`]) so it can be unit-tested
//! against synthetic content; the file is read at exactly one call site,
//! [`load_system_resolv_conf`].
//!
//! On Windows this module compiles but performs no discovery: system
//! resolver discovery there requires the `GetAdaptersAddresses` Win32 API
//! (or reading registry keys) and is future work. Until then, Windows uses
//! the public fallback resolvers configured in [`crate::dns::resolver`].
//!
//! Note for macOS: `/etc/resolv.conf` carries a notice that most processes
//! resolve names through the system routing layer instead. It is still
//! configd-maintained with the current *global default* resolvers, which is
//! the right set for the public zones this resolver queries (`in-addr.arpa`
//! / `ip6.arpa` PTR, `asn.cymru.com` TXT). What it deliberately does NOT
//! capture are macOS *scoped* resolvers — per-interface and per-domain
//! entries (split-DNS VPN configurations; compare `scutil --dns` against
//! resolv.conf). Reading those requires `dns_configuration_copy()` from
//! `dnsinfo.h`, private SPI that Apple removed from the public SDK, and
//! honoring them would mean reimplementing mDNSResponder's per-domain query
//! routing — deliberately out of scope. Callers on split-DNS networks can
//! pin resolvers explicitly via the `*_with_servers` functions. On DNS
//! configuration *changes*, long-running consumers should call
//! [`crate::dns::refresh_system_dns`]; automatic change notification (the
//! `notify(3)` key `com.apple.system.SystemConfiguration.dns_configuration`,
//! as used by Chromium — see <https://issues.chromium.org/issues/40182831>)
//! is a possible future enhancement.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

/// Maximum number of nameservers honored from resolv.conf.
///
/// Mirrors the `MAXNS` constant in glibc's `<resolv.h>` (and the limit
/// documented in resolv.conf(5)): "Up to MAXNS (currently 3) name servers
/// may be listed".
pub const MAXNS: usize = 3;

/// Upper clamp for `options timeout:n`, in seconds.
///
/// resolv.conf(5): "the value for this option is silently capped to 30"
/// (glibc `RES_MAXRETRANS`).
const MAX_TIMEOUT_SECS: u64 = 30;

/// Upper clamp for `options attempts:n`.
///
/// resolv.conf(5): "the value for this option is silently capped to 5"
/// (glibc `RES_MAXRETRY`).
const MAX_ATTEMPTS: u32 = 5;

/// Path of the system resolver configuration file on Unix.
#[cfg(unix)]
const RESOLV_CONF_PATH: &str = "/etc/resolv.conf";

/// System resolver configuration extracted from resolv.conf content.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResolvConf {
    /// Configured nameservers (port 53), in file order, at most [`MAXNS`].
    pub nameservers: Vec<SocketAddr>,
    /// Per-attempt query timeout from `options timeout:n`, clamped to
    /// 1..=30 seconds per resolv.conf(5). `None` if not specified.
    pub timeout: Option<Duration>,
    /// Query attempts per server from `options attempts:n`, clamped to
    /// 1..=5 per resolv.conf(5). `None` if not specified.
    pub attempts: Option<u32>,
}

/// Parse resolv.conf-format text into a [`ResolvConf`].
///
/// Pure function: no filesystem access. Recognizes `nameserver` lines
/// (IPv4 and IPv6 literals) and `options timeout:n attempts:n`; all other
/// directives, comments (`#` or `;`), and garbage lines are ignored.
///
/// Deviations from glibc, chosen for robustness:
/// - Unparseable nameserver values are skipped rather than counted.
/// - Duplicate nameservers are dropped.
/// - Zone-scoped IPv6 link-local addresses (e.g. `fe80::1%en0`) are
///   skipped: carrying the scope requires resolving the interface name to
///   an index (`if_nametoindex`), which we deliberately avoid here.
pub fn parse_resolv_conf(content: &str) -> ResolvConf {
    let mut conf = ResolvConf::default();

    for line in content.lines() {
        // Strip trailing comments, then surrounding whitespace.
        let line = line.split(['#', ';']).next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }

        let mut tokens = line.split_whitespace();
        match tokens.next() {
            Some("nameserver") => {
                if conf.nameservers.len() >= MAXNS {
                    continue;
                }
                let Some(value) = tokens.next() else { continue };
                // Zone-scoped link-local (fe80::1%en0): unsupported, see above.
                if value.contains('%') {
                    continue;
                }
                if let Ok(ip) = value.parse::<IpAddr>() {
                    let server = SocketAddr::new(ip, 53);
                    if !conf.nameservers.contains(&server) {
                        conf.nameservers.push(server);
                    }
                }
            }
            Some("options") => {
                for opt in tokens {
                    if let Some(v) = opt.strip_prefix("timeout:") {
                        if let Ok(secs) = v.parse::<u64>() {
                            conf.timeout =
                                Some(Duration::from_secs(secs.clamp(1, MAX_TIMEOUT_SECS)));
                        }
                    } else if let Some(v) = opt.strip_prefix("attempts:") {
                        if let Ok(n) = v.parse::<u32>() {
                            conf.attempts = Some(n.clamp(1, MAX_ATTEMPTS));
                        }
                    }
                    // Other options (ndots, rotate, ...) are irrelevant to
                    // the single-label absolute queries ftr performs.
                }
            }
            // search/domain/sortlist/garbage: ignored.
            _ => {}
        }
    }

    conf
}

/// Read and parse `/etc/resolv.conf` — the single filesystem call site for
/// system resolver discovery.
///
/// Returns `None` when the file is missing, unreadable, or lists no usable
/// nameservers, in which case the resolver falls back to its built-in
/// public servers (i.e., prior behavior is unchanged).
#[cfg(unix)]
pub fn load_system_resolv_conf() -> Option<ResolvConf> {
    let content = std::fs::read_to_string(RESOLV_CONF_PATH).ok()?;
    let conf = parse_resolv_conf(&content);
    if conf.nameservers.is_empty() {
        None
    } else {
        Some(conf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn v4(a: u8, b: u8, c: u8, d: u8) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(a, b, c, d)), 53)
    }

    fn v6(s: &str) -> SocketAddr {
        SocketAddr::new(IpAddr::V6(s.parse::<Ipv6Addr>().expect("valid IPv6")), 53)
    }

    #[test]
    fn test_empty_file() {
        let conf = parse_resolv_conf("");
        assert!(conf.nameservers.is_empty());
        assert_eq!(conf.timeout, None);
        assert_eq!(conf.attempts, None);
    }

    #[test]
    fn test_single_v4_nameserver() {
        let conf = parse_resolv_conf("nameserver 192.168.1.1\n");
        assert_eq!(conf.nameservers, vec![v4(192, 168, 1, 1)]);
    }

    #[test]
    fn test_multiple_nameservers_in_order() {
        let conf = parse_resolv_conf("nameserver 10.0.0.1\nnameserver 10.0.0.2\n");
        assert_eq!(conf.nameservers, vec![v4(10, 0, 0, 1), v4(10, 0, 0, 2)]);
    }

    #[test]
    fn test_more_than_maxns_truncated() {
        let content = "nameserver 10.0.0.1\n\
                       nameserver 10.0.0.2\n\
                       nameserver 10.0.0.3\n\
                       nameserver 10.0.0.4\n";
        let conf = parse_resolv_conf(content);
        assert_eq!(conf.nameservers.len(), MAXNS);
        assert_eq!(
            conf.nameservers,
            vec![v4(10, 0, 0, 1), v4(10, 0, 0, 2), v4(10, 0, 0, 3)]
        );
    }

    #[test]
    fn test_v6_nameserver() {
        let conf = parse_resolv_conf("nameserver 2606:4700:4700::1111\n");
        assert_eq!(conf.nameservers, vec![v6("2606:4700:4700::1111")]);
    }

    #[test]
    fn test_mixed_v4_v6() {
        let conf = parse_resolv_conf("nameserver 100.100.100.100\nnameserver fd7a:115c:a1e0::53\n");
        assert_eq!(
            conf.nameservers,
            vec![v4(100, 100, 100, 100), v6("fd7a:115c:a1e0::53")]
        );
    }

    #[test]
    fn test_zone_scoped_link_local_skipped() {
        let conf = parse_resolv_conf("nameserver fe80::1%en0\nnameserver 1.0.0.1\n");
        assert_eq!(conf.nameservers, vec![v4(1, 0, 0, 1)]);
    }

    #[test]
    fn test_comments_hash_and_semicolon() {
        let content = "# a full-line hash comment\n\
                       ; a full-line semicolon comment\n\
                       nameserver 9.9.9.9 # trailing comment\n\
                       nameserver 149.112.112.112;trailing\n";
        let conf = parse_resolv_conf(content);
        assert_eq!(
            conf.nameservers,
            vec![v4(9, 9, 9, 9), v4(149, 112, 112, 112)]
        );
    }

    #[test]
    fn test_garbage_lines_ignored() {
        let content = "search example.com\n\
                       domain example.com\n\
                       sortlist 130.155.160.0/255.255.240.0\n\
                       this is not a directive\n\
                       nameserver\n\
                       nameserver not.an.ip.addr\n\
                       nameserver 8.8.8.8\n";
        let conf = parse_resolv_conf(content);
        assert_eq!(conf.nameservers, vec![v4(8, 8, 8, 8)]);
    }

    #[test]
    fn test_duplicate_nameserver_dropped() {
        let content = "nameserver 8.8.8.8\nnameserver 8.8.8.8\nnameserver 8.8.4.4\n";
        let conf = parse_resolv_conf(content);
        assert_eq!(conf.nameservers, vec![v4(8, 8, 8, 8), v4(8, 8, 4, 4)]);
    }

    #[test]
    fn test_leading_whitespace_tolerated() {
        let conf = parse_resolv_conf("   nameserver   192.0.2.53   \n");
        assert_eq!(conf.nameservers, vec![v4(192, 0, 2, 53)]);
    }

    #[test]
    fn test_options_timeout_and_attempts() {
        let conf = parse_resolv_conf("options timeout:2 attempts:3\nnameserver 1.1.1.1\n");
        assert_eq!(conf.timeout, Some(Duration::from_secs(2)));
        assert_eq!(conf.attempts, Some(3));
    }

    #[test]
    fn test_options_clamped() {
        // resolv.conf(5): timeout capped to 30, attempts capped to 5.
        let conf = parse_resolv_conf("options timeout:99 attempts:42\n");
        assert_eq!(conf.timeout, Some(Duration::from_secs(30)));
        assert_eq!(conf.attempts, Some(5));

        // Zero values are clamped up to 1 rather than disabling queries.
        let conf = parse_resolv_conf("options timeout:0 attempts:0\n");
        assert_eq!(conf.timeout, Some(Duration::from_secs(1)));
        assert_eq!(conf.attempts, Some(1));
    }

    #[test]
    fn test_options_garbage_values_ignored() {
        let conf = parse_resolv_conf("options timeout:soon attempts:many ndots:2 rotate\n");
        assert_eq!(conf.timeout, None);
        assert_eq!(conf.attempts, None);
    }

    #[test]
    fn test_realistic_macos_tailscale_file() {
        // Shape of an auto-generated macOS resolv.conf with Tailscale.
        let content = "#\n\
                       # macOS Notice\n\
                       #\n\
                       # This file is not consulted for DNS hostname resolution...\n\
                       #\n\
                       search example.ts.net localdomain\n\
                       nameserver 100.100.100.100\n\
                       nameserver fd7a:115c:a1e0::53\n";
        let conf = parse_resolv_conf(content);
        assert_eq!(
            conf.nameservers,
            vec![v4(100, 100, 100, 100), v6("fd7a:115c:a1e0::53")]
        );
    }
}
