# Refactoring Plan for v0.2.0 - Multi-Mode Probing

## Overview
Refactor ftr to support three probing modes with automatic fallback:
1. **Raw ICMP** - Most privileged, requires CAP_NET_RAW
2. **DGRAM ICMP** - Works as root or with net.ipv4.ping_group_range configured
3. **UDP** - No special permissions required

## Current Architecture Analysis

### Current Implementation
- Uses SOCK_DGRAM with IPPROTO_ICMP exclusively
- Single socket for both sending and receiving
- ICMP packet construction using pnet library
- Direct ICMP parsing for responses

### Key Components to Refactor
1. Socket creation and binding
2. Packet sending logic
3. Packet receiving and parsing logic
4. Error handling and fallback mechanism

## Proposed Architecture

### 1. Socket Abstraction Layer
Create a flexible abstraction that supports multiple protocols and IP versions:
```rust
enum IpVersion {
    V4,
    V6,
}

enum ProbeProtocol {
    Icmp,      // ICMP/ICMPv6
    Udp,       // UDP
    Tcp,       // TCP SYN
}

enum SocketMode {
    Raw,       // Raw socket (full packet control)
    Dgram,     // Datagram socket (kernel handles IP layer)
}

struct ProbeConfig {
    ip_version: IpVersion,
    protocol: ProbeProtocol,
    socket_mode: SocketMode,
}

struct ProbeSocket {
    config: ProbeConfig,
    send_socket: Socket,
    recv_socket: Option<Socket>, // Some modes need separate receive socket
}
```

### 2. Protocol and Mode Combinations

#### IPv4 Modes
1. **Raw ICMP (IPv4)**
   - Socket: `socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)`
   - Full IP + ICMP packet construction
   - Requires: CAP_NET_RAW or root

2. **DGRAM ICMP (IPv4)** - Current implementation
   - Socket: `socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)`
   - ICMP packet only
   - Requires: Root or configured ping_group_range

3. **UDP (IPv4)**
   - Socket: `socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)`
   - UDP to ports 33434+
   - No special permissions

4. **TCP (IPv4)**
   - Socket: `socket(AF_INET, SOCK_RAW, IPPROTO_TCP)` or `SOCK_STREAM`
   - TCP SYN packets
   - Raw requires permissions, stream doesn't

#### IPv6 Modes
1. **Raw ICMPv6**
   - Socket: `socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)`
   - Full IPv6 + ICMPv6 packet construction
   - Requires: CAP_NET_RAW or root

2. **DGRAM ICMPv6**
   - Socket: `socket(AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6)`
   - ICMPv6 packet only
   - Requires: Root or configured ping_group_range

3. **UDP (IPv6)**
   - Socket: `socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)`
   - UDP to ports 33434+
   - No special permissions

4. **TCP (IPv6)**
   - Socket: `socket(AF_INET6, SOCK_RAW, IPPROTO_TCP)` or `SOCK_STREAM`
   - TCP SYN packets
   - Raw requires permissions, stream doesn't

### 3. Unified Trait System

```rust
trait ProbeTarget {
    fn ip_version(&self) -> IpVersion;
    fn destination(&self) -> IpAddr;
}

trait ProbePacket {
    fn set_ttl(&mut self, ttl: u8);
    fn set_identifier(&mut self, id: u16);
    fn to_bytes(&self) -> Vec<u8>;
}

trait ProbeSocket {
    fn send_probe(&self, packet: &dyn ProbePacket, target: &dyn ProbeTarget) -> Result<()>;
    fn recv_response(&self, timeout: Duration) -> Result<ProbeResponse>;
}

struct ProbeResponse {
    from_addr: IpAddr,
    response_type: ResponseType,
    original_probe_id: u16,
    rtt: Duration,
}

enum ResponseType {
    TimeExceeded,           // ICMP TTL exceeded
    DestUnreachable(u8),    // ICMP Dest Unreachable with code
    EchoReply,              // ICMP Echo Reply
    TcpSynAck,              // TCP SYN-ACK
    TcpRst,                 // TCP RST
}
```

### 4. Implementation Strategy

#### Phase 1: Create Core Abstractions
1. Create `probe_socket` module with traits and enums
2. Create `probe_factory` for socket creation with fallback
3. Design packet builders for each protocol/version combination

#### Phase 2: Implement IPv4 Support
1. Refactor current DGRAM ICMP code
2. Add Raw ICMP support
3. Add UDP support
4. Add TCP support

#### Phase 3: Implement IPv6 Support
1. Add ICMPv6 packet builders
2. Add IPv6 socket handling
3. Add UDP6 support
4. Add TCP6 support

#### Phase 4: Integration and Fallback
1. Implement intelligent fallback logic
2. Update main loop to use abstractions
3. Add CLI options for protocol selection
4. Ensure consistent output format

### 5. Intelligent Fallback Logic

```rust
fn create_probe_socket(target: &ProbeTarget, preferred_protocol: Option<ProbeProtocol>) -> Result<Box<dyn ProbeSocket>> {
    let ip_version = target.ip_version();
    
    // Try protocols in order of preference
    let protocols = match preferred_protocol {
        Some(p) => vec![p],
        None => vec![ProbeProtocol::Icmp, ProbeProtocol::Udp, ProbeProtocol::Tcp],
    };
    
    for protocol in protocols {
        // Try raw socket first (most capabilities)
        if let Ok(socket) = try_create_socket(ip_version, protocol, SocketMode::Raw) {
            return Ok(socket);
        }
        
        // Try dgram socket (less privileges needed)
        if protocol != ProbeProtocol::Tcp {
            if let Ok(socket) = try_create_socket(ip_version, protocol, SocketMode::Dgram) {
                return Ok(socket);
            }
        }
        
        // For TCP, try stream socket (no special permissions)
        if protocol == ProbeProtocol::Tcp {
            if let Ok(socket) = try_create_tcp_stream_socket(ip_version) {
                return Ok(socket);
            }
        }
    }
    
    Err(anyhow!("Failed to create any probe socket"))
}
```

### 6. Protocol-Specific Implementation Details

#### UDP Mode (IPv4/IPv6)
- **Sending**: UDP packets to ports 33434 + ttl
- **Receiving**: 
  - Try raw ICMP socket first for full responses
  - Fallback to connected UDP for ECONNREFUSED
- **Matching**: Port number encodes TTL/hop

#### TCP Mode (IPv4/IPv6)
- **Sending**: 
  - Raw: Craft SYN packets
  - Stream: Use non-blocking connect()
- **Receiving**:
  - Raw: Parse TCP flags
  - Stream: Check connect() result
- **Port**: Default 80 (HTTP) or user-specified

#### ICMP/ICMPv6 Differences
- IPv4: Type 8 (Echo Request), Type 0 (Echo Reply)
- IPv6: Type 128 (Echo Request), Type 129 (Echo Reply)
- IPv6 includes more info in Time Exceeded messages

### 6. Testing Strategy
1. Test each mode in isolation
2. Test fallback scenarios
3. Test on systems with different permission configurations
4. Verify consistent output across modes

### 7. User Interface Changes

```
ftr [OPTIONS] <DESTINATION>

Options:
  -4, --ipv4                 Force IPv4
  -6, --ipv6                 Force IPv6
  -I, --icmp                 Use ICMP protocol (default)
  -U, --udp                  Use UDP protocol
  -T, --tcp                  Use TCP protocol
  -p, --port <PORT>          Port for TCP/UDP (default: 80 for TCP, 33434+ for UDP)
  --mode <MODE>              Force socket mode: raw, dgram, stream
  -v, --verbose              Show protocol and socket mode being used
```

Example output with verbose:
```
$ ftr -v google.com
Using DGRAM ICMP mode for IPv4 traceroute to google.com (142.250.80.46)
 1  192.168.1.1    2.1 ms
...
```

## Implementation Order

### v0.2.0 - Core Multi-Mode Support (IPv4 only)
1. Create socket abstraction module with traits
2. Refactor current DGRAM ICMP to use abstractions
3. Implement Raw ICMP mode
4. Implement UDP mode with basic response handling
5. Add intelligent fallback logic
6. Add CLI flags for protocol selection
7. Update documentation

### v0.3.0 - IPv6 Support
1. Add IPv6 abstractions to existing traits
2. Implement ICMPv6 modes (Raw and DGRAM)
3. Implement UDP6 mode
4. Update DNS resolution for IPv6
5. Add -4/-6 flags

### v0.4.0 - TCP Support
1. Implement TCP SYN mode for IPv4
2. Implement TCP SYN mode for IPv6
3. Add port selection options
4. Handle TCP-specific responses

## Module Structure

```
src/
├── main.rs                    # CLI and main loop
├── lib.rs                     # Public API
├── socket/
│   ├── mod.rs                # Socket abstraction traits
│   ├── factory.rs            # Socket creation with fallback
│   ├── icmp_v4.rs           # IPv4 ICMP implementations
│   ├── icmp_v6.rs           # IPv6 ICMP implementations
│   ├── udp.rs               # UDP implementations
│   └── tcp.rs               # TCP implementations
├── packet/
│   ├── mod.rs               # Packet traits
│   ├── icmp.rs              # ICMP packet builders
│   ├── udp.rs               # UDP packet builders
│   └── tcp.rs               # TCP packet builders
└── response/
    ├── mod.rs               # Response parsing traits
    └── parser.rs            # Protocol-specific parsers
```

## Key Design Principles

1. **Trait-based abstraction**: Easy to add new protocols
2. **Graceful degradation**: Always try to work with available permissions
3. **Consistent interface**: Same output format regardless of protocol
4. **Future-proof**: Structure supports easy addition of new protocols
5. **Testable**: Each component can be tested in isolation