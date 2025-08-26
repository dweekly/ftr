## feat: v0.5.1 – Replace BEYOND with TRANSIT/DESTINATION

### Summary

Replaces the BEYOND segment in outputs with TRANSIT and DESTINATION. Library gains helpers to compute these refined segments based on destination ASN.

### Changes

- Library
  - New `ftr::EffectiveSegment` enum and `TracerouteResult::effective_segments()` for refined segments (LAN, ISP, TRANSIT, DESTINATION, UNKNOWN).
  - `TracerouteResult::path_labels()` also available for finer control.
  - Backward-compatible: existing `SegmentType` unchanged.

- CLI
  - Text: Segment display shows TRANSIT or DESTINATION instead of BEYOND when enrichment allows determination.
  - JSON: `segment` field now emits `TRANSIT`/`DESTINATION` instead of `BEYOND`.

### Rationale

Makes it easier to identify which parts of the route traverse transit providers versus the destination’s own network, aiding debugging, performance analysis, and visualization use cases.

### Compatibility

- Library API is additive; 0.5.0 callers remain compatible (no enum breaking changes).
- CLI text/JSON replace BEYOND with refined labels when possible; UNKNOWN used when insufficient enrichment.

### Tests/Quality

- Added unit test for role labeling logic and effective segments.
- `cargo fmt` and `cargo clippy -- -D warnings` clean.

### Screenshots/Examples

```
 9 [TRANSIT] 203.0.113.1  12.345 ms [AS64500 - TRANSIT-NET, US]
10 [DESTINATION] 8.8.8.8  22.456 ms [AS15169 - GOOGLE, US]
```

### Checklist

- [x] Code compiles without warnings
- [x] Tests updated and passing
- [x] Backward compatibility verified
- [x] Release notes added (`RELEASE_NOTES_v0.5.1.md`)
