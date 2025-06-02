# ftr (Fast TraceRoute)

[![Crates.io](https://img.shields.io/crates/v/ftr.svg)](https://crates.io/crates/ftr)
[![Documentation](https://docs.rs/ftr/badge.svg)](https://docs.rs/ftr)
[![License](https://img.shields.io/crates/l/ftr.svg)](https://github.com/dweekly/ftr/blob/main/LICENSE)
[![CI](https://github.com/dweekly/ftr/workflows/CI/badge.svg)](https://github.com/dweekly/ftr/actions)

A fast, parallel ICMP traceroute implementation with ASN lookup.

## Features

- **Parallel probing** - Sends multiple TTL probes concurrently for faster route discovery
- **ASN lookups** - Automatically identifies the autonomous system for each hop
- **Smart classification** - Categorizes hops (e.g., local networks, IXPs, CDNs)
- **Minimal dependencies** - Built with efficiency in mind
- **Cross-platform** - Works on Linux, macOS, and Windows (requires Npcap on Windows)

## Installation

### Using Homebrew

```bash
brew tap dweekly/ftr && brew install ftr
```

### Using Cargo

```bash
cargo install ftr
```

## Usage

Basic usage:
```bash
ftr google.com
```

With options:
```bash
ftr example.com -m 20 -W 5000
```

### Options

- `-s, --start-ttl <START_TTL>` - Starting TTL value (default: 1)
- `-m, --max-hops <MAX_HOPS>` - Maximum number of hops (default: 30)
- `--probe-timeout-ms <MS>` - Timeout for individual probes in milliseconds (default: 1000)
- `-i, --send-launch-interval-ms <MS>` - Interval between launching probes (default: 5)
- `-W, --overall-timeout-ms <MS>` - Overall timeout for the traceroute (default: 3000)

## Example Output

```
ftr to www.facebook.com (157.240.22.35), 30 max hops, 1000ms probe timeout, 3000ms overall timeout

Performing ASN lookups and classifying segments...
 1 [LAN   ] 192.168.1.1 (Private Network)    0.409 ms
 2 [ISP   ] 157.131.132.109 (AS46375 - AS-SONICTELECOM, US)   18.589 ms
 3 [ISP   ] 135.180.179.42 (AS46375 - AS-SONICTELECOM, US)   10.193 ms
 4 [ISP   ] 142.254.59.217 (AS46375 - AS-SONICTELECOM, US)   17.891 ms
 5 [ISP   ] 157.131.209.161 (AS46375 - AS-SONICTELECOM, US)   53.078 ms
 6 [UNKNOWN] * * *
 7 [UNKNOWN] * * *
 8 [UNKNOWN] * * *
 9 [UNKNOWN] * * *
10 [UNKNOWN] * * *
11 [UNKNOWN] * * *
12 [UNKNOWN] * * *
13 [UNKNOWN] * * *
14 [ISP   ] 75.101.33.185 (AS46375 - AS-SONICTELECOM, US)    4.255 ms
15 [BEYOND] 157.240.70.50 (AS32934 - FACEBOOK, US)    4.249 ms
16 [BEYOND] 157.240.112.90 (AS32934 - FACEBOOK, US)    4.192 ms
17 [BEYOND] 129.134.118.175 (AS32934 - FACEBOOK, US)    4.689 ms
18 [BEYOND] 129.134.60.98 (AS32934 - FACEBOOK, US)    6.501 ms
19 [BEYOND] 157.240.22.35 (AS32934 - FACEBOOK, US)    4.515 ms
```

## Requirements

- Rust 1.87.0 or later
- Windows: [Npcap](https://npcap.com/) or WinPcap installed

## Building from Source

```bash
git clone https://github.com/dweekly/ftr
cd ftr
cargo build --release
```

## How It Works

This traceroute implementation:
1. Sends ICMP Echo Request packets with increasing TTL values
2. Captures ICMP Time Exceeded messages from intermediate routers
3. Performs reverse DNS and ASN lookups for discovered hops
4. Uses parallel probing to significantly reduce total scan time

## Performance

Unlike traditional sequential traceroute implementations, this tool sends multiple probes in parallel, dramatically reducing the time needed to map a complete network path.

### Benchmarks

Typical performance improvements over traditional traceroute:
- **30-hop trace**: ~3 seconds vs ~30 seconds (10x faster)
- **15-hop trace**: ~1.5 seconds vs ~15 seconds (10x faster)

The parallel approach maintains accuracy while significantly reducing wait time.

## License

MIT License - see LICENSE file for details

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Author

David Weekly (dweekly)