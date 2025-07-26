# Windows Implementation Plan for ftr v0.2.3

## Current Status

### What's Done
1. ✅ Basic Windows socket skeleton created in `src/socket/windows.rs`
2. ✅ Windows compatibility matrix added to factory
3. ✅ Conditional compilation set up to use Windows sockets
4. ✅ Winsock initialization with OnceLock pattern
5. ✅ Build system configured with Npcap SDK (C:\npcap\npcap-sdk-1.15)
6. ✅ Fixed unused variable warnings with `#[allow(unused_variables)]`
7. ✅ Project builds successfully on Windows ARM64

### What's NOT Working
1. ❌ ICMP packet sending not implemented
2. ❌ ICMP packet receiving not implemented  
3. ❌ Packet parsing for Windows not implemented
4. ❌ UDP mode not implemented for Windows
5. ❌ Error handling needs Windows-specific codes

## Implementation Plan

### Phase 1: Basic ICMP Send/Receive (PRIORITY)

#### 1.1 Test Current State
```powershell
# Build and test what we have
cargo build --target aarch64-pc-windows-msvc
.\target\aarch64-pc-windows-msvc\debug\ftr.exe --version
.\target\aarch64-pc-windows-msvc\debug\ftr.exe 127.0.0.1
```
Expected: "Windows ICMP send not yet implemented" error

#### 1.2 Implement ICMP Packet Creation
In `src/socket/windows.rs`, implement `send_probe()`:
- Create ICMP Echo Request packet structure
- Set ICMP type (8), code (0)
- Add identifier and sequence number from ProbeInfo
- Calculate checksum
- Consider using `pnet` for packet creation or manual implementation

#### 1.3 Implement ICMP Send
- Use `socket2::Socket::send_to()` to send the packet
- Handle Windows-specific errors (WSAGetLastError)
- Set proper TTL before sending

#### 1.4 Implement ICMP Receive
In `recv_response()`:
- Use `socket2::Socket::recv_from()` with timeout
- Parse received IP header to get TTL
- Parse ICMP header to determine packet type
- Handle ICMP Echo Reply (type 0)
- Handle ICMP Time Exceeded (type 11)
- Extract original probe info from ICMP payload

#### 1.5 Test Basic Functionality
```powershell
# Test localhost (should get immediate reply)
.\target\aarch64-pc-windows-msvc\debug\ftr.exe 127.0.0.1

# Test with TTL 1 (should get time exceeded from gateway)
.\target\aarch64-pc-windows-msvc\debug\ftr.exe --start-ttl 1 --max-hops 1 8.8.8.8
```

### Phase 2: Robust Error Handling

#### 2.1 Windows Error Codes
Map Windows socket errors to appropriate responses:
- WSAEACCES (10013) - Permission denied
- WSAEHOSTUNREACH (10065) - No route to host
- WSAETIMEDOUT (10060) - Operation timed out
- Handle admin privilege requirements gracefully

#### 2.2 Packet Validation
- Verify received packets match our probes (check ID/sequence)
- Handle malformed packets gracefully
- Add proper timeout handling

### Phase 3: UDP Support (Optional for v0.2.3)

#### 3.1 Implement UDP Socket
- Create `WindowsUdpSocket` in `windows.rs`
- Send UDP probes to incrementing ports
- Receive ICMP Port Unreachable responses

#### 3.2 Update Factory
- Enable UDP mode for Windows in compatibility matrix
- Add Windows UDP socket creation

### Phase 4: Testing & Polish

#### 4.1 Comprehensive Testing
```powershell
# Test all modes
.\target\aarch64-pc-windows-msvc\debug\ftr.exe google.com
.\target\aarch64-pc-windows-msvc\debug\ftr.exe --json 8.8.8.8
.\target\aarch64-pc-windows-msvc\debug\ftr.exe -v cloudflare.com
.\target\aarch64-pc-windows-msvc\debug\ftr.exe --no-enrich 1.1.1.1

# Test error cases
# Run without admin privileges
# Test with firewall blocking ICMP
# Test with non-existent hosts
```

#### 4.2 Performance Testing
- Compare with Windows `tracert` command
- Ensure parallel probing works correctly
- Test with high packet loss scenarios

#### 4.3 Integration Tests
- Add Windows-specific tests to `tests/`
- Test CLI argument handling
- Test JSON output format

### Phase 5: CI/CD Integration

#### 5.1 GitHub Actions
- Add Windows runner to CI matrix
- Test on both x64 and ARM64 if possible
- Ensure Npcap or WinPcap is available in CI

#### 5.2 Release Artifacts
- Build Windows executables for releases
- Consider creating MSI installer
- Document Windows installation process

## Key Technical Considerations

### ICMP Packet Structure
```
IP Header (20 bytes minimum)
ICMP Header (8 bytes):
  - Type (1 byte): 8 for Echo Request, 0 for Echo Reply, 11 for Time Exceeded
  - Code (1 byte): 0
  - Checksum (2 bytes)
  - Identifier (2 bytes): Use from ProbeInfo
  - Sequence (2 bytes): Use from ProbeInfo
  - Data: Optional payload
```

### Windows Sockets Differences
1. Must call WSAStartup before any socket operations
2. Use WSAGetLastError() for error codes, not errno
3. Some socket options have different names/values
4. Raw sockets may work without admin on Windows 10+ for ICMP

### Testing Commands
```powershell
# Build
cargo build --target aarch64-pc-windows-msvc

# Run with verbose output for debugging
$env:RUST_BACKTRACE=1
.\target\aarch64-pc-windows-msvc\debug\ftr.exe -v 8.8.8.8

# Compare with Windows tracert
tracert 8.8.8.8
.\target\aarch64-pc-windows-msvc\debug\ftr.exe 8.8.8.8
```

## Success Criteria

1. ✅ ftr runs on Windows without crashes
2. ✅ Basic traceroute to common hosts works (google.com, 8.8.8.8)
3. ✅ Proper error messages when run without admin
4. ✅ JSON output works correctly
5. ✅ Performance comparable to native Windows tracert
6. ✅ All existing tests pass on Windows
7. ✅ Documentation updated with Windows instructions

## Next Steps

1. Start with Phase 1.1 - Test current state
2. Implement basic ICMP send (Phase 1.2-1.3)
3. Implement basic ICMP receive (Phase 1.4)
4. Test and iterate until basic traceroute works
5. Move on to error handling and polish

Good luck! Remember to test frequently and commit working code regularly.