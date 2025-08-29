# Release Checklist for v0.6.0

## Pre-Release Testing ✅
- [x] All library tests passing (126 tests)
- [x] All documentation tests passing (24 tests)
- [x] Clippy with strict warnings passes
- [x] Real-world traceroutes tested
- [x] JSON output format verified

## v0.6.0 Feature Summary

### Major Features
1. **TRANSIT and DESTINATION Segments**
   - Replaced generic "BEYOND" with specific TRANSIT/DESTINATION classifications
   - TRANSIT: Networks between ISP and destination (including IXPs)
   - DESTINATION: Hops within the target's ASN

2. **Early Destination ASN Lookup**
   - Destination ASN is looked up at start for proper classification
   - Full ASN info (name, country) displayed in output
   - Available in both CLI and JSON formats

3. **Improved Segment Classification**
   - Public IPs without ASN info classified as TRANSIT (likely IXPs/peering points)
   - Sandwich logic: Unknown/Transit hops between same-type segments inherit that type
   - Better handling of silent hops

4. **Bug Fixes**
   - Probe timeout now properly respected (was hardcoded to 50ms/1000ms)
   - Country code deduplication in ASN names
   - No more empty lines for non-responsive hops at end of trace

5. **Output Improvements**
   - "[No further hops responded; max TTL was X]" message for incomplete traces
   - Cleaner ASN name display without duplicate country codes
   - JSON RTT values rounded to 1 decimal place

## Release Steps

### 1. Update Version References
- [x] Cargo.toml version = "0.6.0"
- [x] JSON output version field shows "0.6.0"
- [ ] Update CHANGELOG.md with release notes

### 2. Final Build & Test
```bash
cargo clean
cargo build --release
cargo test --all
cargo clippy -- -D warnings
```

### 3. Platform Testing
Test on each supported platform:
- [ ] macOS (current development platform)
- [ ] Linux
- [ ] FreeBSD
- [ ] Windows

### 4. Create Git Tag
```bash
git add -A
git commit -m "Release v0.6.0: TRANSIT/DESTINATION segments and improved classification"
git tag -a v0.6.0 -m "Release v0.6.0"
git push origin main
git push origin v0.6.0
```

### 5. GitHub Release
1. Go to GitHub releases page
2. Create new release from v0.6.0 tag
3. Title: "v0.6.0: Enhanced Network Segment Classification"
4. Add release notes from CHANGELOG.md
5. Attach pre-built binaries for each platform

### 6. Crates.io Publication
```bash
cargo publish --dry-run
cargo publish
```

### 7. Post-Release
- [ ] Update README.md if needed
- [ ] Close related GitHub issues
- [ ] Announce on relevant forums/channels

## Known Issues / Future Work
- IXP detection proposal documented for v0.7.0 (see docs/IXP_DETECTION_PROPOSAL.md)
- WHOIS fallback planned for v0.6.1 (see docs/WHOIS_ENHANCEMENT_PROPOSAL.md)
- Some ASN names from Team Cymru lack detail (e.g., "AS6453" instead of "TATA COMMUNICATIONS")

## Testing Commands
```bash
# Basic functionality
./target/release/ftr google.com
./target/release/ftr 8.8.8.8 --json

# Segment classification
./target/release/ftr yahoo.com  # Should show TRANSIT for IXP
./target/release/ftr 164.100.129.11  # Should show message for no further hops

# Timeout testing
./target/release/ftr 10.10.10.10 --probe-timeout-ms 3000

# JSON validation
./target/release/ftr cloudflare.com --json | jq .
```

## Release Notes Draft

### ftr v0.6.0 - Enhanced Network Segment Classification

This release introduces significant improvements to how ftr classifies and displays network segments in traceroute paths.

#### What's New
- **TRANSIT and DESTINATION segments**: More precise classification replacing the generic "BEYOND" label
- **Early destination ASN lookup**: Enables accurate DESTINATION segment identification
- **IXP awareness**: Public IPs without ASN info are now classified as TRANSIT (likely Internet Exchange Points)
- **Sandwich logic**: Intelligent segment inheritance for hops between same-type segments
- **Improved output**: No more empty lines at the end; clear message when max TTL is reached

#### Bug Fixes
- Probe timeout parameter now properly respected (was using hardcoded values)
- ASN names no longer show duplicate country codes
- JSON RTT values properly rounded to 1 decimal place

#### Technical Details
- Full AsnInfo struct stored for destination (not just ASN number)
- Country code suffix stripped from Team Cymru ASN names at ingestion
- Socket timeout configuration properly propagated from CLI arguments

See the [full changelog](CHANGELOG.md) for complete details.