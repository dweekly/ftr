## ftr v0.6.0

### Summary

This release refines segment labeling by replacing BEYOND with two clearer labels:
- DESTINATION: hops in the destination's ASN
- TRANSIT: hops after ISP with different ASNs, before DESTINATION

Destination ASN is now determined directly from the target IP via an early, parallel lookup, improving consistency even when the final hop does not respond.

### Changes

- Library: `SegmentType` now has `Transit` and `Destination` instead of `Beyond`.
- Engine: Starts destination ASN lookup in parallel as soon as the target IP is known.
- CLI Text: Shows `[TRANSIT]` or `[DESTINATION]` when enrichment is available.
- CLI JSON: The `segment` field now emits `TRANSIT` or `DESTINATION` instead of `BEYOND`.
- Docs: Updated README and docs/LIBRARY_USAGE.md for 0.6.0.

### Compatibility

- Breaking for JSON and library consumers: `SegmentType::Beyond` removed.
- If enrichment is insufficient, segment may be `UNKNOWN`.

### Usage

```text
 9 [TRANSIT] 203.0.113.1  12.345 ms [AS64500 - TRANSIT-NET, US]
10 [DESTINATION] 8.8.8.8  22.456 ms [AS15169 - GOOGLE, US]
```

