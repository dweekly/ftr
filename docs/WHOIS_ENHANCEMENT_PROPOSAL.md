# WHOIS Enhancement Proposal for ftr

## Problem Statement

Currently, when ASN lookups fail (IP not announced in BGP), we lose valuable routing context. This particularly affects:
- Internet Exchange Points (IXPs) like Equinix peering facilities
- Private peering arrangements
- Infrastructure IPs not publicly announced

Example: `206.223.116.16` (pat1.sjc.yahoo.com)
- Has reverse DNS indicating Yahoo infrastructure
- No ASN data available (not in BGP)
- WHOIS reveals: Owned by Equinix (206.223.116.0/24)
- This is likely a peering point at an Equinix facility

## Proposed Solution

Add WHOIS lookup as a fallback enrichment source when ASN lookups fail, with aggressive caching.

### Benefits

1. **Better IXP Detection**: Identify Internet Exchange Points (Equinix, AMS-IX, etc.)
2. **Improved Segment Classification**: IXP/peering points should be classified as TRANSIT
3. **Network Ownership Context**: Show organization even when AS not announced
4. **Complete Path Understanding**: Fill gaps in routing visualization

### Implementation Design

#### 1. WHOIS Service

```rust
// New service alongside AsN, Rdns, etc.
pub struct WhoisService {
    cache: Arc<Mutex<WhoisCache>>,
    client: WhoisClient,
}

pub struct WhoisInfo {
    pub cidr: String,           // e.g., "206.223.116.0/24"
    pub organization: String,    // e.g., "Equinix, Inc."
    pub netrange: String,        // e.g., "206.223.116.0 - 206.223.116.255"
}
```

#### 2. Caching Strategy

**Aggressive caching is justified because:**
- IP ownership changes extremely rarely (years/decades)
- WHOIS data is per netblock, not per IP
- WHOIS servers often rate-limit queries

**Cache design:**
```rust
struct WhoisCache {
    // Key: CIDR block (e.g., "206.223.116.0/24")
    // Value: (WhoisInfo, expiry_time)
    entries: HashMap<String, (WhoisInfo, Instant)>,
    
    // TTL: Very long (30+ days reasonable)
    default_ttl: Duration::from_secs(30 * 24 * 60 * 60),
}
```

#### 3. Integration Points

**Enrichment flow:**
1. Try ASN lookup (existing)
2. If ASN fails but IP is public:
   - Check WHOIS cache for containing CIDR
   - If miss, perform WHOIS lookup
   - Cache result by CIDR block
3. Use organization info for classification

**Segment classification enhancement:**
```rust
// Known IXP organizations
const IXP_ORGS: &[&str] = &[
    "Equinix",
    "AMS-IX", 
    "LINX",
    "DE-CIX",
    // ... more IXPs
];

// If no ASN but WHOIS shows IXP org -> TRANSIT
if whois_info.is_ixp() {
    SegmentType::Transit
}
```

### Display Enhancement

Current output:
```
12 [ISP   ] pat1.sjc.yahoo.com (206.223.116.16) 10.972 ms
```

Enhanced output with WHOIS:
```
12 [TRANSIT] pat1.sjc.yahoo.com (206.223.116.16) 10.972 ms [Equinix IXP]
```

JSON enhancement:
```json
{
  "ttl": 12,
  "segment": "TRANSIT",
  "address": "206.223.116.16",
  "hostname": "pat1.sjc.yahoo.com",
  "asn_info": null,
  "whois_info": {
    "organization": "Equinix, Inc.",
    "cidr": "206.223.116.0/24",
    "is_ixp": true
  },
  "rtt_ms": 10.972
}
```

### WHOIS Client Options

1. **Direct WHOIS Protocol** (port 43)
   - Pro: No dependencies
   - Con: Need to handle different server formats

2. **RDAP (REST-based successor to WHOIS)**
   - Pro: JSON responses, standardized
   - Con: Not all RIRs fully support it yet

3. **Hybrid Approach**
   - Try RDAP first (cleaner)
   - Fall back to WHOIS if needed

### Performance Considerations

- WHOIS lookups only for IPs without ASN data (minority of hops)
- Aggressive caching minimizes lookups
- Could pre-populate cache with common IXP ranges
- Async/parallel lookups maintain performance

### Privacy & Rate Limiting

- Respect WHOIS server rate limits
- Consider adding config option to disable WHOIS lookups
- Cache sharing between traces reduces queries

## Future Enhancements

1. **IXP Database**: Maintain list of known IXP IP ranges
2. **Peering Detection**: Identify direct peering relationships
3. **Organization Mapping**: Map org names to well-known entities
4. **AS Relationship Data**: Combine with BGP relationship data

## Backwards Compatibility

- New field `whois_info` is optional in JSON
- Existing code continues to work
- Feature can be disabled via config flag

## Example Implementation Priority

1. Phase 1: Basic WHOIS lookup and caching
2. Phase 2: IXP detection and TRANSIT classification
3. Phase 3: RDAP support
4. Phase 4: Advanced relationship mapping

This enhancement would provide valuable routing context currently missing from traceroute tools, especially for understanding Internet infrastructure and peering arrangements.