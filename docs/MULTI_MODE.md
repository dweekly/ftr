# Multi-Mode Probing in ftr v0.2.1

## Overview

Starting with v0.2.1, ftr supports multiple probing modes with automatic fallback. This allows the tool to work in various permission environments and network configurations.

## Supported Modes

### ICMP Modes

1. **Raw ICMP** (Highest privilege)
   - Socket: `SOCK_RAW` with `IPPROTO_ICMP`
   - Requires: CAP_NET_RAW capability or root (except Windows)
   - Features: Full control over IP and ICMP headers
   - Platform: Linux, macOS, Windows, FreeBSD, OpenBSD

2. **DGRAM ICMP** (Medium privilege)
   - Socket: `SOCK_DGRAM` with `IPPROTO_ICMP` 
   - Requires: Root or configured ping_group_range (Linux), no root needed (macOS)
   - Features: Kernel handles IP layer
   - Platform: Linux, macOS (NOT supported on FreeBSD/OpenBSD)

### UDP Mode

3. **UDP** (Platform dependent)
   - Socket: `SOCK_DGRAM` with `IPPROTO_UDP`
   - Linux: No privileges required (uses `IP_RECVERR`)
   - Other platforms: Requires root (needs raw ICMP socket)
   - Features: Traditional UDP traceroute (ports 33434+)
   - Platform: All
   - Note: Linux can receive ICMP errors via `IP_RECVERR` without root

### TCP Mode (Future - v0.3.0)

4. **TCP SYN** (Planned)
   - Socket: `SOCK_RAW` or `SOCK_STREAM`
   - Features: TCP-based traceroute

## Automatic Fallback

The socket factory automatically tries modes in order of capability:

```
ICMP Raw → ICMP DGRAM → UDP
```

For example:
- Running as root: Uses Raw ICMP for best performance
- Running as user with ping_group_range: Uses DGRAM ICMP
- Running as regular user: Falls back to UDP

## Command Line Usage

```bash
# Default (automatic mode selection)
ftr google.com

# Force UDP mode
ftr -U google.com

# Force ICMP mode (will fail if insufficient permissions)
ftr -I google.com

# TCP mode (not yet implemented)
ftr -T google.com -p 443
```

## Architecture

### Socket Abstraction

All probe modes implement the `ProbeSocket` trait:

```rust
pub trait ProbeSocket: Send + Sync {
    fn mode(&self) -> ProbeMode;
    fn set_ttl(&self, ttl: u8) -> Result<()>;
    fn send_probe(&self, target: IpAddr, probe_info: ProbeInfo) -> Result<()>;
    fn recv_response(&self, timeout: Duration) -> Result<Option<ProbeResponse>>;
    fn destination_reached(&self) -> bool;
}
```

### Factory Pattern

The `create_probe_socket` function handles mode selection:

```rust
let socket = create_probe_socket(
    target_ip,
    Some(ProbeProtocol::Udp)  // Preferred protocol
)?;
```

## Implementation Status

- [x] Socket abstraction layer
- [x] Factory with fallback logic
- [x] IPv4 Raw ICMP
- [x] IPv4 DGRAM ICMP  
- [x] IPv4 UDP
- [ ] IPv6 support (v0.3.0)
- [ ] TCP support (v0.3.0)

## Testing

Run the socket test example:

```bash
# Test default mode selection
cargo run --example test_socket -- google.com

# Test UDP mode
cargo run --example test_socket -- google.com --udp
```

## Platform Compatibility Matrix

| Platform | Raw ICMP | DGRAM ICMP | UDP (send) | UDP (recv ICMP) | Non-root Option |
|----------|----------|------------|------------|-----------------|-----------------|
| Linux    | Root     | Root/ping_group | No root | No root (IP_RECVERR) | ✓ UDP or DGRAM |
| macOS    | Root     | No root    | No root    | Root            | ✓ DGRAM ICMP    |
| Windows  | No admin | N/A        | No admin   | No admin        | ✓ Raw ICMP      |
| FreeBSD  | Root     | N/A        | No root    | Root            | ✗ None          |
| OpenBSD  | Root     | N/A        | No root    | Root            | ✗ None          |

## Privilege Requirements Summary

Privilege requirements vary by mode and platform:

- **Raw ICMP**: Root or CAP_NET_RAW (except Windows which works without admin)
- **DGRAM ICMP**: 
  - Linux: Root or configured ping_group_range
  - macOS: Works without root
  - FreeBSD/OpenBSD: Not supported by OS
- **UDP**: 
  - Linux: No privileges required (uses `IP_RECVERR`)
  - Other platforms: Root (needs raw ICMP socket for responses)

Key insights:
- Linux: UDP mode works completely without privileges
- macOS: DGRAM ICMP works without privileges
- Windows: Raw ICMP works without admin privileges
- FreeBSD/OpenBSD: All traceroute modes require root

## Troubleshooting

### "Failed to create any probe socket"

This means none of the modes could get the required privileges. Solutions:

1. **Run with sudo** (works for all modes):
   ```bash
   sudo ftr google.com
   ```

2. **Configure ping_group_range** (Linux only, enables DGRAM ICMP):
   ```bash
   echo "net.ipv4.ping_group_range = 0 65535" | sudo tee -a /etc/sysctl.conf
   sudo sysctl -p
   ```
   After this, DGRAM ICMP mode will work without sudo.

### "UDP mode requires root privileges"

UDP traceroute sends UDP packets (no privileges needed) but must receive ICMP "Port Unreachable" responses, which requires a raw socket. There's no way around this requirement.

### Platform-Specific Notes

- **Linux**: Supports all modes. Configure ping_group_range for unprivileged ICMP.
- **macOS**: Raw sockets require root. DGRAM ICMP works without root for all users.
- **Windows**: Uses native Windows ICMP API (IcmpCreateFile). Raw ICMP works without admin.
- **FreeBSD**: All modes require root. DGRAM ICMP is not supported by the OS.
- **OpenBSD**: All modes require root. DGRAM ICMP is not supported by the OS.