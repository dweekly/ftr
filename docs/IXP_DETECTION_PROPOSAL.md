# IXP/Peering Point Detection Proposal

## Overview
This proposal outlines a systematic approach to identify Internet Exchange Points (IXPs) and peering locations in traceroute paths, building on ftr's existing ASN enrichment capabilities.

## Motivation
- Current traceroutes show ASN transitions but don't identify where peering occurs
- Reverse DNS hints (e.g., "100.ae1.nrd1.equinix-sj.sonic.net") suggest IXP locations
- Understanding peering points helps with network troubleshooting and path analysis

## Research Findings

### Available Data Sources

#### 1. PeeringDB API (https://www.peeringdb.com/api/)
- **Status**: Active, publicly accessible REST API
- **Provides**: IXP locations, member ASNs, IP prefixes used by IXPs
- **Key endpoints**:
  - `/api/ix` - IXP information
  - `/api/netixlan` - Network-IXP connections
  - `/api/ixpfx` - IXP IP prefixes
- **Example**: Can query which ASNs peer at "Equinix SV1/SV5/SV10"

#### 2. IXP IP Prefix Databases
- PeeringDB maintains authoritative list of IP ranges used by IXPs
- Packet Clearing House (PCH) provides additional IXP data
- CAIDA's IXP dataset for research purposes

#### 3. Reverse DNS Patterns
- Many IXPs use identifiable hostname patterns:
  - Facility codes: `equinix-sj`, `ams-ix`, `de-cix`
  - Peering indicators: `.ix.`, `.peering.`, `.exchange.`
  - Geographic hints: city codes, facility names

### Detection Methods

#### Method 1: IP Prefix Matching
```
1. Detect ASN transition: AS46375 → AS6453
2. Check if intermediate IPs fall within known IXP prefixes
3. Validate both ASNs are members of that IXP
```

#### Method 2: Reverse DNS Analysis
```
1. Parse rDNS for IXP/facility indicators
2. Cross-reference with PeeringDB facility names
3. Score confidence based on pattern matches
```

#### Method 3: RTT Analysis
```
1. Detect RTT anomalies at ASN boundaries
2. Sudden RTT drops often indicate local peering
3. Geographic validation using geolocation
```

## Implementation Plan

### Phase 1: Data Integration
1. **PeeringDB Client Module** (`src/ixp/peeringdb.rs`)
   - Async client for PeeringDB API
   - Cache IXP prefixes and memberships
   - Periodic updates (configurable, default 24h)

2. **IXP Database** (`src/ixp/database.rs`)
   - Store IXP prefixes as CIDR blocks
   - Index by ASN for quick membership lookups
   - Include facility names and locations

### Phase 2: Detection Engine
1. **IXP Detector Service** (`src/ixp/detector.rs`)
   ```rust
   pub struct IxpInfo {
       pub name: String,
       pub facility: Option<String>,
       pub location: String,
       pub member_asns: Vec<u32>,
       pub confidence: f32,  // 0.0 to 1.0
   }
   ```

2. **Detection Algorithm**:
   - For each ASN transition in traceroute
   - Check if IPs match IXP prefixes
   - Analyze rDNS patterns
   - Calculate confidence score

### Phase 3: Integration
1. **Extend SegmentType**:
   ```rust
   pub enum SegmentType {
       Lan,
       Isp,
       Ixp,        // New
       Transit,
       Destination,
       Unknown,
   }
   ```

2. **Update TracerouteResult**:
   - Add `ixp_crossings: Vec<IxpCrossing>`
   - Include IXP info in hop enrichment

3. **CLI Output**:
   ```
   12 [ISP   ] 100.ae1.nrd1.equinix-sj.sonic.net (75.101.33.185) 5.580 ms [AS46375]
   -- [IXP: Equinix SV1 - San Jose, AS46375 ↔ AS6453] --
   13 [TRANSIT] 216.6.52.80 5.583 ms [AS6453 - TATA]
   ```

### Phase 4: Configuration
- `--enable-ixp-detection`: Enable IXP detection (default: false initially)
- `--ixp-cache-dir`: Cache directory for PeeringDB data
- `--ixp-update-interval`: How often to refresh IXP data

## Validation Approach
1. Test against known routes with confirmed IXP crossings
2. Compare with looking glass data from major networks
3. Validate against traIXroute results for accuracy baseline

## Expected Accuracy
- **High confidence (>90%)**: When IP matches IXP prefix AND both ASNs are members
- **Medium confidence (60-90%)**: When rDNS patterns match known IXP facilities
- **Low confidence (<60%)**: Based solely on RTT analysis or geographic hints

## Privacy & Performance Considerations
- Cache PeeringDB data locally to minimize API calls
- Respect rate limits (suggested: max 100 queries/hour)
- Make IXP detection optional to avoid overhead

## Future Enhancements
1. BGP route views integration for validation
2. Historical peering relationship tracking
3. Anomaly detection for routing changes
4. Integration with network monitoring tools

## References
- PeeringDB API Documentation: https://www.peeringdb.com/apidocs/
- traIXroute paper: "Detecting IXPs in Traceroute Paths Using traIXroute"
- CAIDA IXP Dataset: https://www.caida.org/data/ixps/

## Target Release
Proposed for v0.7.0 or later, after v0.6.0 segment classification stabilizes.