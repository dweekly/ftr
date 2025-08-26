## ftr v0.5.1 (Unreleased)

### Summary

This release adds path role labeling to both the CLI and the library:
- DESTINATION: hops in the destination's ASN
- TRANSIT: hops in different ASNs after the ISP segment and before DESTINATION

These labels make it easier to visually and programmatically identify the portion of the path that traverses transit networks versus the destination network.

### Changes

- Library: Added `ftr::PathLabel` enum (`Destination`, `Transit`).
- Library: Added `TracerouteResult::path_labels() -> Vec<Option<PathLabel>>` to compute per-hop roles without breaking existing types.
- CLI Text: Shows roles inline with segment, e.g. `[BEYOND | TRANSIT]` or `[BEYOND | DESTINATION]` when enrichment is enabled.
- CLI JSON: Adds optional `path_label` field for each hop with values `"TRANSIT" | "DESTINATION" | null`.

### Compatibility

- Backward compatible with 0.5.0 callers: existing structs/enums unchanged; new API is additive.
- CLI output remains compatible; added role is appended to the existing segment display.
- JSON schema is compatible; a new optional field is added.

### Usage

- Programmatic:
```rust
let labels = result.path_labels();
for (hop, label) in result.hops.iter().zip(labels) {
    if let Some(label) = label {
        println!("hop {}: {:?}", hop.ttl, label);
    }
}
```

- CLI (text):
```
 9 [BEYOND | TRANSIT] 203.0.113.1  12.345 ms [AS64500 - TRANSIT-NET, US]
10 [BEYOND | DESTINATION] 8.8.8.8  22.456 ms [AS15169 - GOOGLE, US]
```

- CLI (JSON):
```json
{
  "ttl": 10,
  "segment": "BEYOND",
  "address": "8.8.8.8",
  "hostname": "dns.google",
  "asn_info": { "asn": 15169, "name": "GOOGLE" },
  "rtt_ms": 22.456,
  "path_label": "DESTINATION"
}
```

### Notes

- Labeling applies to hops classified as `BEYOND` and requires ASN enrichment.
- If the destination ASN cannot be determined, labels may be `null`.

### Acknowledgments

- Feature request and guidance by project maintainers.

