# FreeBSD Implementation Plan for ftr v0.2.4

## Research Summary

### FreeBSD Socket Capabilities

1. **ICMP Support**:
   - **Raw ICMP sockets**: Requires root privileges (same as Linux)
   - **DGRAM ICMP sockets**: FreeBSD supports unprivileged ICMP sockets via `SOCK_DGRAM` with `IPPROTO_ICMP`
   - Similar to macOS, FreeBSD allows non-root ICMP echo requests when using DGRAM sockets
   - Requires `net.inet.icmp.icmplim` sysctl to be set appropriately

2. **UDP Support**:
   - Standard UDP sockets work normally
   - Receiving ICMP errors for UDP requires raw socket (root)
   - No equivalent to Linux's `IP_RECVERR` 

3. **Key Differences from Linux/macOS**:
   - FreeBSD's DGRAM ICMP is very similar to macOS
   - No `IP_RECVERR` like Linux
   - Strong compatibility with POSIX standards
   - Better security model for ICMP than Linux (DGRAM works without special groups)

### FreeBSD-Specific Considerations

1. **System Calls and APIs**:
   - Standard BSD sockets API
   - `sendto()` and `recvfrom()` for DGRAM ICMP
   - `setsockopt()` with `IP_TTL` for setting TTL
   - No special FreeBSD-specific APIs needed

2. **Permissions**:
   - Raw sockets: require root
   - DGRAM ICMP: works for regular users
   - UDP: no special permissions for sending, but receiving ICMP requires root

3. **Platform Detection**:
   - Use `#[cfg(target_os = "freebsd")]`
   - FreeBSD version considerations (11.x, 12.x, 13.x, 14.x)

## Implementation Plan

### Phase 1: Code Reuse Analysis

Since FreeBSD DGRAM ICMP works very similarly to macOS, we can likely reuse most of the macOS implementation:

1. **Analyze current macOS implementation**:
   - Review `src/socket/icmp_v4.rs` - `DgramIcmpV4Socket`
   - Check if the implementation is already generic enough
   - Identify any macOS-specific code

2. **Test existing code on FreeBSD**:
   - The current code might already work on FreeBSD
   - Need to verify DGRAM ICMP behavior matches macOS

### Phase 2: Update Compatibility Matrix

1. **Update `src/socket/factory.rs`**:
   ```rust
   #[cfg(target_os = "freebsd")]
   {
       match (protocol, socket_mode) {
           (ProbeProtocol::Icmp, SocketMode::Raw) => RequiresRoot,
           (ProbeProtocol::Icmp, SocketMode::Dgram) => Works,  // Like macOS!
           (ProbeProtocol::Udp, SocketMode::Raw) => RequiresRoot,
           (ProbeProtocol::Udp, SocketMode::Dgram) => RequiresRoot, // Needs raw ICMP
           (ProbeProtocol::Tcp, SocketMode::Raw) => RequiresRoot,
           (ProbeProtocol::Tcp, SocketMode::Stream) => Works,
           _ => NotSupported,
       }
   }
   ```

2. **Update socket selection logic**:
   - FreeBSD should prefer DGRAM ICMP when not root (like macOS)
   - Fall back to TCP if needed

### Phase 3: Implementation

1. **Minimal code changes needed**:
   - Most likely just conditional compilation updates
   - Possibly no new socket implementation needed

2. **Specific areas to update**:
   - `factory.rs`: Add FreeBSD compatibility matrix
   - `icmp_v4.rs`: Ensure DGRAM implementation works on FreeBSD
   - `main.rs`: Update any OS-specific messages

### Phase 4: Testing

1. **Test matrix**:
   - FreeBSD 13.x (latest stable)
   - FreeBSD 14.x (current)
   - Both as root and non-root
   - All socket modes (raw ICMP, dgram ICMP, UDP, TCP)

2. **Specific test cases**:
   ```bash
   # Non-root tests
   $ ./ftr 8.8.8.8                    # Should use DGRAM ICMP
   $ ./ftr --socket-mode dgram 8.8.8.8  # Explicit DGRAM
   
   # Root tests
   $ sudo ./ftr 8.8.8.8               # Should use Raw ICMP
   $ sudo ./ftr --protocol udp 8.8.8.8  # UDP mode
   ```

3. **CI Integration**:
   - Add FreeBSD to GitHub Actions matrix (if available)
   - Or use Cirrus CI for FreeBSD testing

### Phase 5: Documentation

1. **Update README.md**:
   - Add FreeBSD to supported platforms
   - Document any FreeBSD-specific requirements
   - Add FreeBSD installation instructions

2. **Update CHANGELOG.md**:
   - Document FreeBSD support

## Technical Implementation Details

### Expected Code Changes

1. **src/socket/factory.rs**:
   - Add FreeBSD target in `get_compatibility()`
   - Add FreeBSD case in `create_probe_socket_with_port()`
   - Update error messages for FreeBSD

2. **src/socket/icmp_v4.rs**:
   - Verify `DgramIcmpV4Socket` works on FreeBSD
   - May need minor adjustments for error handling

3. **Cargo.toml**:
   - No new dependencies expected
   - Existing `socket2` and `pnet` should work on FreeBSD

### Potential Challenges

1. **ICMP Rate Limiting**:
   - FreeBSD has `net.inet.icmp.icmplim` sysctl
   - Default might be restrictive
   - Need to handle rate limit errors gracefully

2. **CI/CD**:
   - GitHub Actions doesn't have native FreeBSD runners
   - Options:
     - Use `vmactions/freebsd-vm` action
     - Use Cirrus CI for FreeBSD
     - Cross-compile and test manually

3. **Packet Structure**:
   - Verify ICMP packet structure matches expectations
   - FreeBSD should follow RFC standards

## Testing Commands

```bash
# Build on FreeBSD
$ cargo build --release

# Test as regular user
$ ./target/release/ftr -v google.com    # Should show "Using Datagram ICMP IPv4 mode"
$ ./target/release/ftr localhost        # Test localhost

# Test as root
$ sudo ./target/release/ftr -v google.com  # Should show "Using Raw ICMP IPv4 mode"
$ sudo ./target/release/ftr --protocol udp google.com

# Test error cases
$ ./target/release/ftr --socket-mode raw google.com  # Should fail with permission error
```

## Success Criteria

1. ✅ Non-root traceroute works using DGRAM ICMP
2. ✅ Root traceroute works with all modes
3. ✅ Proper fallback when modes unavailable
4. ✅ Clear error messages for FreeBSD users
5. ✅ Tests pass on FreeBSD 13.x and 14.x
6. ✅ Documentation updated

## Estimated Effort

Given that FreeBSD DGRAM ICMP is very similar to macOS:
- **Low complexity**: Most code should already work
- **Primary work**: Testing and verification
- **Time estimate**: 2-4 hours of development + testing

## Next Steps

1. Set up FreeBSD test environment (VM or cloud instance)
2. Test current code on FreeBSD without modifications
3. Implement minimal changes needed
4. Comprehensive testing
5. Documentation updates