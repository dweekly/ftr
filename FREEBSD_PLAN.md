# FreeBSD Implementation Plan for ftr v0.2.4

## Research Summary

### FreeBSD Socket Capabilities

1. **ICMP Support**:
   - **Raw ICMP sockets**: Requires root privileges (same as Linux)
   - **DGRAM ICMP sockets**: **NOT SUPPORTED** - FreeBSD 14.3 returns "Protocol not supported" (errno 43)
   - Unlike macOS, FreeBSD does NOT support unprivileged ICMP via DGRAM sockets
   - This was confirmed through testing with both C and Rust programs
   - `net.inet.icmp.icmplim` sysctl controls ICMP rate limiting (default: 200)

2. **UDP Support**:
   - Standard UDP sockets work normally
   - Receiving ICMP errors for UDP requires running a parallel raw ICMP socket (root) to capture TTL-exceeded responses
   - No equivalent to Linux's `IP_RECVERR` 

3. **Key Differences from Linux/macOS**:
   - **Critical**: FreeBSD does NOT support DGRAM ICMP (unlike macOS)
   - No `IP_RECVERR` like Linux
   - Strong compatibility with POSIX standards
   - Requires root for ICMP traceroute (no unprivileged option)
   - TCP Stream mode: Needs implementation for non-root traceroute
   - Raw sockets: Standard BSD behavior, requires root

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

4. **Firewall Considerations**:
   - PF (Packet Filter) may block raw sockets by default
   - BPF (Berkeley Packet Filter) restrictions may apply
   - Users should be warned about potential firewall interference

## Implementation Plan

### Phase 1: Implementation Analysis

Since FreeBSD does NOT support DGRAM ICMP, we need a different approach:

1. **Current status**:
   - Code builds successfully on FreeBSD 14.3
   - DGRAM ICMP fails with "Protocol not supported"
   - Raw ICMP requires root (standard behavior)
   - TCP Stream mode not yet implemented

2. **Priority for FreeBSD support**:
   - Implement TCP Stream mode for non-root traceroute
   - Ensure Raw ICMP works correctly with root
   - Add proper FreeBSD detection and error messages

### Phase 2: Update Compatibility Matrix

1. **Update `src/socket/factory.rs`** (COMPLETED):
   ```rust
   #[cfg(target_os = "freebsd")]
   {
       match (protocol, socket_mode) {
           (ProbeProtocol::Icmp, SocketMode::Raw) => RequiresRoot,
           (ProbeProtocol::Icmp, SocketMode::Dgram) => NotSupported,  // NOT SUPPORTED!
           (ProbeProtocol::Udp, SocketMode::Raw) => RequiresRoot,
           (ProbeProtocol::Udp, SocketMode::Dgram) => RequiresRoot, // Needs raw ICMP
           (ProbeProtocol::Tcp, SocketMode::Raw) => RequiresRoot,
           (ProbeProtocol::Tcp, SocketMode::Stream) => Works,
           _ => NotSupported,
       }
   }
   ```

2. **Update socket selection logic** (COMPLETED):
   - FreeBSD prefers TCP Stream mode when not root
   - Falls back to UDP, then ICMP (all require root)

### Phase 3: Implementation

1. **Required implementations**:
   - **TCP Stream mode**: Create new `tcp.rs` module for TCP-based traceroute
   - **Raw ICMP verification**: Test that existing Raw ICMP works with root

2. **Specific areas completed**:
   - ✅ `factory.rs`: Updated FreeBSD compatibility matrix
   - ✅ `factory.rs`: Separated FreeBSD from macOS in protocol selection
   - ✅ `factory.rs`: Added FreeBSD-specific error messages
   - ✅ `icmp_v4.rs`: Added IP_HDRINCL support for FreeBSD raw sockets
   - ✅ `main.rs`: Added FreeBSD root privilege check at startup
   - ✅ `main.rs`: Added ca_root_nss warning for HTTPS failures
   - ✅ `Cargo.toml`: Added libc dependency for FreeBSD
   
3. **Current Status**:
   - FreeBSD support is functional with root privileges
   - Raw ICMP mode works correctly
   - Public IP detection works with ca_root_nss installed
   - Non-root users get clear error message
   - TCP Stream mode not needed (would still require root for ICMP responses)

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
   - Use `vmactions/freebsd-vm` GitHub Action for FreeBSD testing
   - Configure for FreeBSD 13.x (stable) and 14.x (current)
   - Add FreeBSD-specific smoke tests with `#[cfg(target_os="freebsd")]`

### Phase 5: Documentation

1. **Update README.md**:
   - Add FreeBSD to supported platforms
   - Document any FreeBSD-specific requirements
   - Add FreeBSD installation instructions (pkg or binary tarball)
   - Include firewall warnings (PF/BPF)

2. **Update CHANGELOG.md**:
   - Document FreeBSD support under v0.2.4
   - Remember to update version in Cargo.toml

3. **Update MULTI_MODE.md**:
   - Include FreeBSD's DGRAM ICMP path
   - Document compatibility matrix for FreeBSD

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
   - Verify `socket2` and `pnet` build cleanly on FreeBSD (confirmed: they do)
   - Update version to 0.2.4 when ready
   - Note: `native-tls-vendored` is now conditionally enabled only on Linux for static linking

### Build Dependencies for FreeBSD

When building on FreeBSD, the following packages must be installed:
```bash
pkg install -y rust openssl perl5 pkgconf
```

- `rust`: Provides rustc and cargo (FreeBSD bundles them together)
- `openssl`: Required by native-tls (system OpenSSL library)
- `perl5`: Required for OpenSSL build system if vendored
- `pkgconf`: Required for finding system libraries

### Runtime Dependencies for FreeBSD

For full functionality (including public IP detection and ASN lookups):
```bash
pkg install -y ca_root_nss
```

- `ca_root_nss`: Mozilla CA certificate bundle required for HTTPS connections
  - Without this package, public IP detection will fail silently
  - This affects ISP detection and hop classification features

### Potential Challenges

1. **ICMP Rate Limiting**:
   - FreeBSD has `net.inet.icmp.icmplim` sysctl
   - Default might be restrictive
   - Need to handle rate limit errors gracefully
   - Include diagnostic check for restrictive `icmplim` settings
   - Warn users if defaults are too restrictive

2. **CI/CD**:
   - GitHub Actions doesn't have native FreeBSD runners
   - Use `vmactions/freebsd-vm` action for testing
   - Example configuration:
     ```yaml
     - name: Test on FreeBSD
       uses: vmactions/freebsd-vm@v1
       with:
         usesh: true
         prepare: |
           pkg install -y rust cargo
         run: |
           cargo build --release
           cargo test
           ./target/release/ftr 8.8.8.8
     ```

3. **Packet Structure**:
   - Verify ICMP packet structure matches expectations
   - FreeBSD should follow RFC standards

## Testing Commands

```bash
# Build on FreeBSD
$ cargo build --release

# Check ICMP rate limiting
$ sysctl net.inet.icmp.icmplim

# Test as regular user
$ ./target/release/ftr -v google.com    # Should show "Using Datagram ICMP IPv4 mode"
$ ./target/release/ftr localhost        # Test localhost

# Test as root
$ sudo ./target/release/ftr -v google.com  # Should show "Using Raw ICMP IPv4 mode"
$ sudo ./target/release/ftr --protocol udp google.com

# Test error cases
$ ./target/release/ftr --socket-mode raw google.com  # Should fail with permission error

# Test TCP Stream mode
$ ./target/release/ftr --protocol tcp google.com  # Should use TCP Stream mode
```

## Success Criteria

1. ❌ Non-root traceroute works using DGRAM ICMP - **NOT SUPPORTED by FreeBSD**
2. ✅ Root traceroute works with Raw ICMP mode
3. ✅ Clear error message when run without root privileges
4. ✅ FreeBSD-specific error messages and root check
5. ✅ Tests pass on FreeBSD 14.3 ARM64
6. ✅ Documentation updated (README with installation instructions)
7. ⏳ CI/CD pipeline includes FreeBSD testing (configuration ready)
8. ⏳ FreeBSD-specific smoke tests (pending)
9. ✅ Installation instructions for FreeBSD (build from source)
10. ✅ ca_root_nss dependency documented for HTTPS support

## Actual Implementation Results

Initial assumption that FreeBSD supports DGRAM ICMP like macOS was **incorrect**:
- FreeBSD does NOT support DGRAM ICMP (returns "Protocol not supported")
- Required fixes:
  - Added IP_HDRINCL support for raw sockets
  - Added libc dependency for FreeBSD
  - Added root privilege check at startup
  - Added ca_root_nss dependency for HTTPS
- **Actual effort**: ~4 hours including discovery, implementation, and testing
- **Result**: Full FreeBSD support with root privileges only

## Remaining Tasks

1. ✅ ~~FreeBSD implementation~~ - COMPLETED
2. ⏳ Add FreeBSD-specific integration tests
3. ⏳ Configure `vmactions/freebsd-vm` in CI/CD pipeline
4. ⏳ Update MULTI_MODE.md with FreeBSD information
5. ⏳ Test on FreeBSD 13.x (currently tested on 14.3)
6. ⏳ Consider adding to FreeBSD ports collection