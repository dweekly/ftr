# ftr (Fast TraceRoute)

[![Crates.io](https://img.shields.io/crates/v/ftr.svg)](https://crates.io/crates/ftr)
[![License](https://img.shields.io/crates/l/ftr.svg)](https://github.com/dweekly/ftr/blob/main/LICENSE)
[![CI](https://github.com/dweekly/ftr/workflows/CI/badge.svg)](https://github.com/dweekly/ftr/actions)
[![codecov](https://codecov.io/gh/dweekly/ftr/graph/badge.svg)](https://codecov.io/gh/dweekly/ftr)

A fast, parallel ICMP traceroute implementation with ASN lookup.

## Features

- **Parallel probing** - Sends multiple TTL probes concurrently for faster route discovery
- **ASN lookups** - Automatically identifies the autonomous system for each hop
- **Reverse DNS** - Shows hostnames for each hop when available
- **ISP detection** - Identifies your ISP by detecting your public IP's ASN
- **Smart classification** - Categorizes hops as LAN, ISP, or BEYOND
- **CGNAT aware** - Properly handles Carrier Grade NAT (100.64.0.0/10)
- **Early exit optimization** - Completes instantly when destination is reached
- **Minimal dependencies** - Built with efficiency in mind
- **Cross-platform** - Works on Linux, macOS, Windows, FreeBSD, and OpenBSD

## Installation

### Windows

#### Installation Options

**Option 1: Download Pre-built Binary** (when available)
- Download the latest Windows binary from the [releases page](https://github.com/dweekly/ftr/releases/latest)
- Extract and add to your PATH, or run directly

**Option 2: Build from Source**
```bash
git clone https://github.com/dweekly/ftr
cd ftr
cargo build --release
# The binary will be at target/release/ftr.exe
```

### macOS

#### Using Homebrew

```bash
brew tap dweekly/ftr && brew install ftr
```

### Linux

#### Using APT Repository (Debian/Ubuntu)

If you are on a Debian-based Linux distribution (like Ubuntu, Debian, Mint, etc.), you can install ftr using our APT repository for easy installation and updates.

1. Update your package list and install prerequisites:

```bash
sudo apt-get update
sudo apt-get install -y curl gpg ca-certificates
```

2. Add the ftr repository GPG key:

```bash
# Create the directory for GPG keys if it doesn't exist
sudo mkdir -p /usr/share/keyrings

# Download and save the GPG key
sudo curl -sSL https://apt.networkweather.com/networkweather.noarmor.gpg -o /usr/share/keyrings/networkweather-archive-keyring.gpg
```

3. Add the ftr APT repository:

```bash
# Automatically detect your system architecture and add the appropriate repository
ARCH=$(dpkg --print-architecture)
echo "deb [signed-by=/usr/share/keyrings/networkweather-archive-keyring.gpg arch=$ARCH] https://apt.networkweather.com stable main" | sudo tee /etc/apt/sources.list.d/networkweather.list
```

4. Install ftr:

```bash
sudo apt-get update
sudo apt-get install ftr
```

Once installed, ftr will be updated along with your other system packages when you run `sudo apt-get upgrade`.

### Direct Download (Debian/Ubuntu)

Alternatively, you can download the .deb package directly from the [latest release](https://github.com/dweekly/ftr/releases/latest):

```bash
# For x86_64/amd64
wget https://github.com/dweekly/ftr/releases/latest/download/ftr_<version>_amd64.deb
sudo dpkg -i ftr_<version>_amd64.deb

# For ARM64/aarch64
wget https://github.com/dweekly/ftr/releases/latest/download/ftr_<version>_arm64.deb
sudo dpkg -i ftr_<version>_arm64.deb
```

### FreeBSD

#### Using pkg

```bash
# Install from FreeBSD ports (when available)
pkg install ftr
```

#### Building from Source

**Build Dependencies:**
```bash
# Required for building
pkg install -y rust openssl perl5 pkgconf

# Required for runtime functionality
pkg install -y ca_root_nss
```

**Build and Install:**
```bash
# Clone and build
git clone https://github.com/dweekly/ftr
cd ftr
cargo build --release

# Install the binary
sudo cp target/release/ftr /usr/local/bin/
```

**Important Notes:**
- FreeBSD requires **root privileges** for all traceroute operations (no unprivileged ICMP support)
- The `ca_root_nss` package is required for HTTPS connections (public IP detection and ASN lookups)
- Without `ca_root_nss`, you'll see "Warning: Failed to detect public IP"

**Usage on FreeBSD:**
```bash
# Must run as root
sudo ftr google.com

# Or make the binary setuid root
sudo chown root:wheel /usr/local/bin/ftr
sudo chmod u+s /usr/local/bin/ftr
# Then run normally
ftr google.com
```

### OpenBSD

#### Using pkg_add

```bash
# Install from OpenBSD ports (when available)
pkg_add ftr
```

#### Building from Source

**Build Dependencies:**
```bash
# Required for building
pkg_add rust git

# Optional but recommended
pkg_add rsync jq
```

**Build and Install:**
```bash
# Clone and build
git clone https://github.com/dweekly/ftr
cd ftr
cargo build --release

# Install the binary
doas cp target/release/ftr /usr/local/bin/
```

**Important Notes:**
- OpenBSD requires **root privileges** for all traceroute operations (no unprivileged ICMP support)
- Works identically to FreeBSD - requires root/doas for all operations

**Usage on OpenBSD:**
```bash
# Must run as root
doas ftr google.com

# Or make the binary setuid root
doas chown root:wheel /usr/local/bin/ftr
doas chmod u+s /usr/local/bin/ftr
# Then run normally
ftr google.com
```

### Using Cargo

```bash
cargo install ftr
```

*Note: Cargo installation will be available once ftr is published to crates.io.*

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
- `--no-enrich` - Disable ASN lookup and segment classification
- `--no-rdns` - Disable reverse DNS lookups

## Example Output

```
ftr to google.com (142.251.46.174), 30 max hops, 1000ms probe timeout, 3000ms overall timeout

Performing ASN lookups, reverse DNS lookups and classifying segments...
 1 [LAN   ] unifi.localdomain (192.168.1.1) [Private Network]    2.854 ms
 2 [ISP   ] lo0.bras2.rdcyca01.sonic.net (157.131.132.109) [AS46375 - AS-SONICTELECOM, US]    3.861 ms
 3 [ISP   ] 135-180-179-42.dsl.dynamic.sonic.net (135.180.179.42) [AS46375 - AS-SONICTELECOM, US]    6.342 ms
 4 [ISP   ] ae8.cr2.lsatca11.sonic.net (142.254.59.217) [AS46375 - AS-SONICTELECOM, US]   16.705 ms
 5 [ISP   ] ae2.cr1.lsatca11.sonic.net (157.131.209.161) [AS46375 - AS-SONICTELECOM, US]   12.469 ms
 6 [BEYOND] be3402.ccr31.sjc04.atlas.cogentco.com (154.54.80.241) [AS174 - COGENT-174, US]    3.904 ms
 7 [BEYOND] be3142.ccr41.sjc03.atlas.cogentco.com (154.54.42.89) [AS174 - COGENT-174, US]    3.989 ms
 8 [BEYOND] tata.sjc03.atlas.cogentco.com (154.54.13.62) [AS174 - COGENT-174, US]    3.177 ms
 9 [BEYOND] 72.14.195.206 [AS15169 - GOOGLE, US]    6.174 ms
10 [BEYOND] 108.170.252.33 [AS15169 - GOOGLE, US]    5.316 ms
11 [BEYOND] 142.250.49.206 [AS15169 - GOOGLE, US]    4.892 ms
12 [BEYOND] sfo07s16-in-f14.1e100.net (142.251.46.174) [AS15169 - GOOGLE, US]    3.275 ms
Detected ISP from public IP 192.184.165.158: AS46375 (AS-SONICTELECOM, US)
```

## Requirements

- Rust 1.82.0 or later (for building from source)
- Platform-specific requirements:
  - **Linux**: Root privileges or configured ping_group_range for ICMP functionality
  - **macOS**: Root privileges may be required for raw socket access
  - **Windows**: No additional requirements (uses native Windows ICMP API)
    - Note: Windows Firewall may prompt for permission on first run
  - **FreeBSD**: Root privileges required for ICMP (no DGRAM ICMP support)
  - **OpenBSD**: Root privileges required for ICMP (no DGRAM ICMP support)

### Privilege Requirements

Privilege requirements vary by mode and platform:
- **ICMP modes**: Root or ping_group_range configuration
- **UDP mode**: 
  - Linux: No privileges required (uses `IP_RECVERR`)
  - Other platforms: Root (needs raw socket for ICMP responses)

On Linux, you can enable DGRAM ICMP for non-root users:
```bash
sudo sysctl -w net.ipv4.ping_group_range="0 65535"
```

## Building from Source

### Prerequisites

- **Rust**: Version 1.82.0 or later (install from [rustup.rs](https://rustup.rs/))
- **Platform-specific dependencies**:
  - **Linux**: Standard build tools (gcc/clang, make)
  - **macOS**: Xcode Command Line Tools
  - **Windows**: Visual Studio Build Tools or MinGW
  - **FreeBSD**: `pkg install -y rust openssl perl5 pkgconf rsync`
  - **OpenBSD**: `pkg_add rust`

### Build Steps

```bash
git clone https://github.com/dweekly/ftr
cd ftr

# Install git hooks (IMPORTANT: prevents issues caught by CI)
./.githooks/install-hooks.sh
# OR configure git to use .githooks directory:
# git config core.hooksPath .githooks

cargo build --release

# Binary will be at: target/release/ftr
```

### Platform-Specific Notes

- **All platforms**: The git hooks ensure code quality standards are met before commits

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