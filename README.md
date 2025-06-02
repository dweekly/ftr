# ftr (Fast TraceRoute)

[![Crates.io](https://img.shields.io/crates/v/ftr.svg)](https://crates.io/crates/ftr)
[![Documentation](https://docs.rs/ftr/badge.svg)](https://docs.rs/ftr)
[![License](https://img.shields.io/crates/l/ftr.svg)](https://github.com/dweekly/tracer/blob/main/LICENSE)
[![CI](https://github.com/dweekly/tracer/workflows/CI/badge.svg)](https://github.com/dweekly/tracer/actions)

A fast, parallel ICMP traceroute implementation with ASN lookup.

## Features

- **Parallel probing** - Sends multiple TTL probes concurrently for faster route discovery
- **ASN lookups** - Automatically identifies the autonomous system for each hop
- **Smart classification** - Categorizes hops (e.g., local networks, IXPs, CDNs)
- **Minimal dependencies** - Built with efficiency in mind
- **Cross-platform** - Works on Linux, macOS, and Windows (requires Npcap on Windows)

## Installation

```bash
cargo install ftr
```

## Usage

Basic usage:
```bash
sudo ftr google.com
```

With options:
```bash
sudo ftr example.com -m 20 -W 5000
```

### Options

- `-s, --start-ttl <START_TTL>` - Starting TTL value (default: 1)
- `-m, --max-hops <MAX_HOPS>` - Maximum number of hops (default: 30)
- `--probe-timeout-ms <MS>` - Timeout for individual probes in milliseconds (default: 1000)
- `-i, --send-launch-interval-ms <MS>` - Interval between launching probes (default: 5)
- `-W, --overall-timeout-ms <MS>` - Overall timeout for the traceroute (default: 3000)

## Example Output

```
Minimalist ICMP Traceroute to 8.8.8.8
 1  192.168.1.1      1.234 ms    (Local/Private)
 2  10.0.0.1         5.678 ms    (Local/Private)
 3  203.0.113.1      8.901 ms    AS64496 Example ISP
 4  198.51.100.1    12.345 ms    AS64497 Transit Provider
 5  192.0.2.1       15.678 ms    AS64498 Another Network
 6  8.8.8.8         18.901 ms    AS15169 Google LLC
```

## Requirements

- Rust 1.70.0 or later
- Root/administrator privileges (required for raw ICMP sockets)
- Windows: [Npcap](https://npcap.com/) or WinPcap installed

## Building from Source

```bash
git clone https://github.com/dweekly/tracer
cd tracer
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